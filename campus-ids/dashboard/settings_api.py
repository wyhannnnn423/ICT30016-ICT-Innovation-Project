"""
settings_api.py
------------------------
The two web endpoints behind the dashboard's Settings panel.

  GET  /api/status     capture check and the PC's current IP (read-only, polled by the page)
  GET  /api/settings   current settings (anyone who can open the dashboard)
  POST /api/settings   change settings  (only from the PC that runs the dashboard)

Every change is checked (ids_settings.validate), applied to the running detector
immediately and written to the settings file, so it survives a restart.
"""

from flask import jsonify, request

import ids_settings as S


def register(app, get_detector, settings_path):
    def can_edit():
        # 1) the request must come from this PC, 2) the Host header must be localhost or an IP
        return request.remote_addr in S.local_addresses() and S.host_header_ok(request.host)

    @app.get("/api/settings")
    def read_settings():
        return jsonify({
            "settings": get_detector().get_settings(),
            "defaults": S.DEFAULTS,
            "detected_ip": S.detect_lan_ip(),
            "can_edit": can_edit(),
        })

    @app.get("/api/status")
    def read_status():
        detector = get_detector()
        return jsonify({
            "capture": detector.capture_status(),
            "detected_ip": S.detect_lan_ip(),
            "own_ips": detector.own.to_list(),
            "auto_own_ip": detector.auto_own_ip,
        })

    @app.post("/api/settings")
    def change_settings():
        if not can_edit():
            return jsonify(ok=False, errors=["Settings can only be changed from the PC that runs the dashboard."]), 403
        if not request.is_json:                    # also stops simple cross-site form posts
            return jsonify(ok=False, errors=["Send the settings as JSON."]), 415
        detector = get_detector()
        clean, errors = S.validate(request.get_json(silent=True), detector.get_settings())
        if errors:
            return jsonify(ok=False, errors=errors), 400
        detector.apply_settings(S.resolve_own_ips(clean, S.detect_lan_ip()))
        warning = None
        try:
            S.save(settings_path, detector.get_settings())
        except OSError as e:
            warning = f"Applied, but could not be saved to disk: {e}"
        return jsonify(ok=True, settings=detector.get_settings(), warning=warning)
