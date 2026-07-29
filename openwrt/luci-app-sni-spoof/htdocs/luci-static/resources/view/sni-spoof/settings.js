'use strict';
'require view';
'require form';
'require uci';
'require network';
'require rpc';
'require ui';

var callStatus = rpc.declare({
	object: 'luci.sni-spoof',
	method: 'status'
});

var callCheckUpdate = rpc.declare({
	object: 'luci.sni-spoof',
	method: 'check_update'
});

var callUpdate = rpc.declare({
	object: 'luci.sni-spoof',
	method: 'update'
});

var callUpdateStatus = rpc.declare({
	object: 'luci.sni-spoof',
	method: 'update_status'
});

var callDiagnose = rpc.declare({
	object: 'luci.sni-spoof',
	method: 'diagnose'
});

function showReport(title, text) {
	ui.showModal(title, [
		E('pre', {
			'style': 'max-height:60vh;overflow:auto;white-space:pre-wrap;' +
			         'font-size:90%;line-height:1.35'
		}, text || _('(no output)')),
		E('div', { 'class': 'right' }, [
			E('button', {
				'class': 'btn cbi-button-neutral',
				'click': ui.hideModal
			}, _('Close'))
		])
	]);
}

// Poll the detached updater and stream its log into the open modal. The update
// outlives the request that started it, so this is how we follow along.
function followUpdate(pre) {
	return callUpdateStatus().then(function (res) {
		res = res || {};
		pre.textContent = res.log || _('Working...');
		pre.scrollTop = pre.scrollHeight;

		if (res.running || !res.finished)
			return new Promise(function (resolve) {
				window.setTimeout(function () { resolve(followUpdate(pre)); }, 2000);
			});

		return res;
	});
}

function runUpdate() {
	var pre = E('pre', {
		'style': 'max-height:50vh;overflow:auto;white-space:pre-wrap;font-size:90%'
	}, _('Starting...'));

	ui.showModal(_('Updating SNI Spoofing'), [
		E('p', {}, _('Downloading and installing the release. Do not reboot the router until this finishes.')),
		pre,
		E('div', { 'class': 'right' }, [
			E('button', {
				'class': 'btn cbi-button-neutral',
				'click': ui.hideModal
			}, _('Run in background'))
		])
	]);

	return callUpdate().then(function (res) {
		if (!res || !res.started) {
			pre.textContent = (res && res.error) || _('Could not start the update.');
			return;
		}
		return followUpdate(pre).then(function (final) {
			final = final || {};
			if (final.success) {
				ui.addNotification(null,
					E('p', {}, _('Updated to %s. Reloading...').format(final.version || '?')),
					'info');
				window.setTimeout(function () { window.location.reload(); }, 2500);
			} else {
				ui.addNotification(null,
					E('p', {}, _('The update failed. The previous version was restored; see the log for details.')),
					'error');
			}
		});
	}).catch(function (e) {
		pre.textContent = _('Update request failed: ') + e;
	});
}

return view.extend({
	load: function () {
		return Promise.all([
			uci.load('sni-spoof'),
			network.getDevices(),
			// Status is best-effort: an older install may not have the rpcd
			// backend yet, and the settings form must still render without it.
			callStatus().catch(function () { return null; })
		]);
	},

	render: function (data) {
		var m, s, o;
		var devices = (data && data[1]) || [];
		var status = (data && data[2]) || null;

		m = new form.Map('sni-spoof', _('SNI Spoofing'),
			_('Local DPI-bypass relay. In Passwall2, point a node at the listen ' +
			  'address/port below. The relay dials your server IP while sending a ' +
			  'fake SNI, so on-path DPI sees an allowed hostname. It touches no ' +
			  'firewall or routing — it just does its own work.'));

		s = m.section(form.NamedSection, 'main', 'sni-spoof', _('Settings'));
		s.anonymous = true;

		o = s.option(form.Flag, 'enabled', _('Enabled'));
		o.rmempty = false;

		o = s.option(form.Value, 'listen_host', _('Listen address'),
			_('Keep 127.0.0.1 so only this router (Passwall2) can reach it.'));
		o.datatype = 'ipaddr';
		o.placeholder = '127.0.0.1';

		o = s.option(form.Value, 'listen_port', _('Listen port'),
			_('Set your Passwall2 node port to this value.'));
		o.datatype = 'port';
		o.placeholder = '40443';

		o = s.option(form.Value, 'connect_ip', _('Server IP'),
			_('The real destination the relay connects to (your proxy server). ' +
			  'You <em>must</em> add this IP to Passwall2’s direct/bypass list. ' +
			  'Otherwise Passwall2 re-proxies the relay’s own outbound connection, ' +
			  'the injector never sees it on the wire, and every connection is ' +
			  'dropped after two seconds. Use <em>Run diagnostics</em> below to check.'));
		o.datatype = 'ipaddr';

		o = s.option(form.Value, 'connect_port', _('Server port'));
		o.datatype = 'port';
		o.placeholder = '443';

		o = s.option(form.Value, 'fake_sni', _('Fake SNI'),
			_('The allowed hostname DPI will see, e.g. chatgpt.com.'));
		o.placeholder = 'chatgpt.com';

		o = s.option(form.ListValue, 'interface', _('Network interface'),
			_('Outbound interface the relay binds to. <em>Default</em> follows the ' +
			  'default route and is the right choice almost always. If you pin one, ' +
			  'pick the device that actually holds the WAN address (e.g. pppoe-wan) — ' +
			  'a device without an IPv4 leaves the relay unable to bind.'));
		o.value('default', _('Default (default route)'));
		devices.forEach(function (dev) {
			var name = dev.getName();
			if (!name || name == 'lo')
				return;
			var v4 = (dev.getIPAddrs() || []).filter(function (a) {
				return a.indexOf(':') < 0;
			});
			var label = v4.length ? (name + ' (' + v4[0] + ')') : (name + ' — ' + _('no IPv4'));
			o.value(name, label);
		});

		o = s.option(form.Flag, 'no_bpf', _('Disable kernel packet filter'),
			_('Skip the in-kernel BPF capture filter and use the Python filter alone. ' +
			  'Slightly more CPU, but immune to a kernel whose BPF drops our packets. ' +
			  'Worth trying if the log says no outbound SYN was ever observed.'));
		o.rmempty = false;

		o = s.option(form.Flag, 'bind_interface', _('Bind capture to one interface'),
			_('Capture only on the outbound device instead of all of them. Off by ' +
			  'default: binding by name is unreliable on some virtual NICs.'));
		o.rmempty = false;
		o.optional = true;

		/* ---- Status & Maintenance ------------------------------------- */

		s = m.section(form.NamedSection, 'main', 'sni-spoof', _('Status & Maintenance'));
		s.anonymous = true;

		o = s.option(form.DummyValue, '_status', _('Status'));
		o.rawhtml = true;
		o.cfgvalue = function () {
			if (!status)
				return '<em>' + _('Status backend unavailable — re-run openwrt/install.sh.') + '</em>';

			var bits = [];
			bits.push(status.running
				? '<span style="color:#2a7">' + _('Running') + '</span>'
				: '<span style="color:#c33">' + _('Stopped') + '</span>');
			if (status.running && !status.listening)
				bits.push('<span style="color:#c33">' + _('not listening on %s').format(status.listen) + '</span>');
			else if (status.listening)
				bits.push(_('listening on %s').format(status.listen));
			bits.push(_('version %s').format(status.version || '?'));

			var html = bits.join(' &middot; ');
			if (status.last_message)
				html += '<br /><small style="opacity:.8">' + status.last_message.replace(/[<>&]/g, '') + '</small>';
			return html;
		};

		o = s.option(form.Button, '_diagnose', _('Diagnostics'),
			_('Checks the runtime, the service, routing, and whether Passwall2 or the ' +
			  'firewall is redirecting the relay’s own traffic — the usual reason ' +
			  'connections die after two seconds.'));
		o.inputtitle = _('Run diagnostics');
		o.inputstyle = 'apply';
		o.onclick = function () {
			ui.showModal(_('Diagnostics'), [ E('p', { 'class': 'spinning' }, _('Running checks...')) ]);
			return callDiagnose().then(function (res) {
				showReport(_('Diagnostics'), res && res.report);
			}).catch(function (e) {
				showReport(_('Diagnostics'), _('Failed to run diagnostics: ') + e);
			});
		};

		o = s.option(form.Button, '_check', _('Updates'),
			_('Checks GitHub for a newer release of this tool.'));
		o.inputtitle = _('Check for updates');
		o.inputstyle = 'reload';
		o.onclick = function () {
			return callCheckUpdate().then(function (res) {
				res = res || {};
				if (res.error) {
					ui.addNotification(null, E('p', {}, res.error), 'warning');
				} else if (res.update_available) {
					ui.addNotification(null, E('p', {},
						_('Version %s is available (installed: %s). Use “Update now” to install it.')
							.format(res.latest, res.installed)), 'info');
				} else {
					ui.addNotification(null, E('p', {},
						_('Already up to date (%s).').format(res.installed)), 'info');
				}
			}).catch(function (e) {
				ui.addNotification(null, E('p', {}, _('Update check failed: ') + e), 'error');
			});
		};

		o = s.option(form.Button, '_update', _('Update from GitHub'),
			_('Downloads the latest release and reinstalls it. The current install is ' +
			  'backed up first and restored automatically if anything goes wrong.'));
		o.inputtitle = _('Update now');
		o.inputstyle = 'negative';
		o.onclick = function () {
			ui.showModal(_('Update from GitHub'), [
				E('p', {}, _('This downloads the latest release and reinstalls the relay, ' +
				             'then restarts the service. Continue?')),
				E('div', { 'class': 'right' }, [
					E('button', {
						'class': 'btn cbi-button-neutral',
						'click': ui.hideModal
					}, _('Cancel')),
					' ',
					E('button', {
						'class': 'btn cbi-button-negative',
						'click': function () { runUpdate(); }
					}, _('Update now'))
				])
			]);
		};

		return m.render();
	}
});
