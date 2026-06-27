# -*- coding: utf-8 -*-

from burp import IBurpExtender, ITab, IHttpListener, IMessageEditorController
from javax.swing import (
    JPanel, JButton, JLabel, JTextArea, JScrollPane,
    JTabbedPane, BorderFactory, JTable,
    JSplitPane, SwingUtilities, JMenuItem, JPopupMenu, Box, UIManager
)
from javax.swing.table import DefaultTableModel
from javax.swing.border import EmptyBorder, CompoundBorder, MatteBorder
from javax.swing.event import ChangeListener
from java.awt import (
    BorderLayout, FlowLayout, Color, Font,
    Dimension, GridBagLayout, GridBagConstraints, Insets, Cursor
)
from java.awt import Toolkit
from java.awt.event import MouseAdapter
from javax.sound.sampled import AudioFormat, AudioSystem, DataLine, SourceDataLine
import math
import re
import threading


SKIP_EXTENSIONS = (
    '.js', '.css', '.png', '.jpg', '.jpeg', '.gif',
    '.svg', '.ico', '.woff', '.woff2', '.ttf', '.eot',
    '.map', '.zip'
)

SKIP_METHODS = ('GET', 'OPTIONS')

TOOL_PROXY = 4

COLOR_BG         = Color(30,  30,  35)
COLOR_SURFACE    = Color(40,  42,  48)
COLOR_SURFACE2   = Color(50,  52,  60)
COLOR_BORDER     = Color(65,  68,  78)
COLOR_ACCENT     = Color(99,  179, 237)
COLOR_VULN       = Color(252, 90,  90)
COLOR_VULN_DIM   = Color(120, 35,  35)
COLOR_SAFE       = Color(72,  199, 116)
COLOR_SAFE_DIM   = Color(25,  90,  50)
COLOR_REVIEW     = Color(251, 191, 36)
COLOR_REVIEW_DIM = Color(110, 80,  10)
COLOR_TEXT       = Color(220, 222, 228)
COLOR_TEXT_DIM   = Color(140, 145, 158)
COLOR_ROW_ALT    = Color(45,  47,  54)

REVIEW_IGNORE_PHRASES = ("not found", "bad request")

FALLBACK_MONO   = Font("Monospaced", Font.PLAIN,  12)
FALLBACK_MONO_B = Font("Monospaced", Font.BOLD,   12)
FALLBACK_UI     = Font("SansSerif",  Font.PLAIN,  12)
FALLBACK_UI_B   = Font("SansSerif",  Font.BOLD,   12)
FALLBACK_SMALL  = Font("SansSerif",  Font.PLAIN,  11)


class ReadOnlyTableModel(DefaultTableModel):

    def isCellEditable(self, row, col):
        return False


class StyledTable(JTable):

    def __init__(self, model, row_color, alt_color):
        JTable.__init__(self, model)
        self._row_color = row_color
        self._alt_color = alt_color

    def prepareRenderer(self, renderer, row, col):
        component = JTable.prepareRenderer(self, renderer, row, col)
        if self.isRowSelected(row):
            component.setBackground(self._row_color)
            component.setForeground(Color.WHITE)
        elif row % 2 == 0:
            component.setBackground(COLOR_SURFACE)
            component.setForeground(COLOR_TEXT)
        else:
            component.setBackground(self._alt_color)
            component.setForeground(COLOR_TEXT)
        component.setFont(FALLBACK_MONO)
        return component


class PillButton(JButton):

    def __init__(self, text, bg, fg=Color.WHITE):
        JButton.__init__(self, text)
        self.setOpaque(True)
        self.setBackground(bg)
        self.setForeground(fg)
        self.setFont(FALLBACK_UI_B)
        self.setFocusPainted(False)
        self.setBorderPainted(False)
        self.setCursor(Cursor(Cursor.HAND_CURSOR))
        self.setMargin(Insets(5, 14, 5, 14))


class TabChangeListener(ChangeListener):

    def __init__(self, tabs, label_configs):
        self._tabs    = tabs
        self._configs = label_configs

    def stateChanged(self, e):
        selected = self._tabs.getSelectedIndex()
        for i, (lbl, active_color) in enumerate(self._configs):
            if i == selected:
                lbl.setForeground(active_color)
                lbl.setFont(FALLBACK_UI_B)
            else:
                lbl.setForeground(COLOR_TEXT_DIM)
                lbl.setFont(FALLBACK_UI)


class BurpExtender(IBurpExtender, ITab, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()
        callbacks.setExtensionName("BAC-TESTER")

        self._enabled        = False
        self._victim_header  = ""
        self._victim_headers = []

        self._vuln_details   = []
        self._safe_details   = []
        self._review_details = []

        self._vuln_current   = {}
        self._safe_current   = {}
        self._review_current = {}

        self._request_count  = 0
        self._vuln_count     = 0

        self._build_ui()
        callbacks.registerHttpListener(self)
        callbacks.addSuiteTab(self)

        print("[BAC-TESTER] Loaded - paste victim session in Config tab then click Enable.")

    def getTabCaption(self):
        return "BAC-TESTER"

    def getUiComponent(self):
        return self._main_panel

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if toolFlag != TOOL_PROXY:
            return
        if not messageIsRequest:
            return
        if not self._enabled:
            return
        if not self._victim_headers:
            return

        try:
            request      = messageInfo.getRequest()
            request_info = self._helpers.analyzeRequest(messageInfo)
            url          = str(request_info.getUrl())
            method       = str(request_info.getMethod()).upper()
            headers      = request_info.getHeaders()

            if method in SKIP_METHODS:
                return

            path_lower = url.split('?')[0].lower()
            for ext in SKIP_EXTENSIONS:
                if path_lower.endswith(ext):
                    return

            modified_headers = self._inject_victim_session(headers)
            body_offset      = request_info.getBodyOffset()
            body_bytes       = request[body_offset:]
            modified_request = self._helpers.buildHttpMessage(modified_headers, body_bytes)

            path_only = re.sub(r'^https?://[^/]+', '', url.split('?')[0])
            if '?' in url:
                path_only += '?' + url.split('?', 1)[1]

            service = messageInfo.getHttpService()

            self._request_count += 1
            SwingUtilities.invokeLater(lambda: self._stats_label.setText(
                "  Tested: {}   Vulns: {}".format(self._request_count, self._vuln_count)
            ))

            t = threading.Thread(
                target=self._send_and_evaluate,
                args=(method, path_only, service, modified_request)
            )
            t.daemon = True
            t.start()

        except Exception as ex:
            print("[BAC-TESTER] Listener error: " + str(ex))

    def _send_and_evaluate(self, method, path, service, modified_request):
        try:
            resp_obj   = self._callbacks.makeHttpRequest(service, modified_request)
            resp_bytes = resp_obj.getResponse() if resp_obj else None

            if resp_bytes:
                resp_info   = self._helpers.analyzeResponse(resp_bytes)
                mod_status  = resp_info.getStatusCode()
                body_offset = resp_info.getBodyOffset()
                resp_body   = self._helpers.bytesToString(resp_bytes[body_offset:])
                resp_str    = self._helpers.bytesToString(resp_bytes)
            else:
                mod_status = 0
                resp_body  = ""
                resp_str   = ""

            verdict = self._verdict(mod_status, resp_body)

            if verdict is None:
                return

            mod_req_str = self._helpers.bytesToString(modified_request)

            def add_row(_method=method, _path=path,
                        _ms=str(mod_status), _v=verdict,
                        _mod_req=mod_req_str,
                        _mod_bytes=modified_request,
                        _resp=resp_str,
                        _resp_bytes=resp_bytes if resp_bytes else b'',
                        _svc=service):

                detail = {
                    'modified_request'   : _mod_req,
                    'response'           : _resp,
                    'service'            : _svc,
                    'modified_req_bytes' : _mod_bytes,
                    'response_bytes'     : _resp_bytes
                }

                if _v == "VULN":
                    self._vuln_count += 1
                    self._vuln_model.addRow([_method, _path, _ms])
                    self._vuln_details.append(detail)
                    row_idx = self._vuln_model.getRowCount() - 1
                    self._vuln_table.scrollRectToVisible(
                        self._vuln_table.getCellRect(row_idx, 0, True)
                    )
                    self._vuln_tab_label.setText(" [!] Vulnerable ({})".format(
                        self._vuln_model.getRowCount()
                    ))
                    self._stats_label.setText(
                        "  Tested: {}   Vulns: {}".format(self._request_count, self._vuln_count)
                    )
                    beep_t = threading.Thread(target=self._play_beep)
                    beep_t.daemon = True
                    beep_t.start()

                elif _v == "SAFE":
                    self._safe_model.addRow([_method, _path, _ms])
                    self._safe_details.append(detail)
                    row_idx = self._safe_model.getRowCount() - 1
                    self._safe_table.scrollRectToVisible(
                        self._safe_table.getCellRect(row_idx, 0, True)
                    )
                    self._safe_tab_label.setText(" [+] Secure ({})".format(
                        self._safe_model.getRowCount()
                    ))

                else:
                    self._review_model.addRow([_method, _path, _ms])
                    self._review_details.append(detail)
                    row_idx = self._review_model.getRowCount() - 1
                    self._review_table.scrollRectToVisible(
                        self._review_table.getCellRect(row_idx, 0, True)
                    )
                    self._review_tab_label.setText(" [?] Suspicious ({})".format(
                        self._review_model.getRowCount()
                    ))

            SwingUtilities.invokeLater(add_row)

        except Exception as ex:
            print("[BAC-TESTER] _send_and_evaluate error: " + str(ex))

    def _verdict(self, mod_status, resp_body):
        body_lower = resp_body.lower() if resp_body else ""

        if "forbidden" in body_lower or "user is not allowed" in body_lower:
            return "SAFE"

        if mod_status == 403:
            return "SAFE"

        if 200 <= mod_status <= 299:
            return "VULN"

        has_body   = bool(body_lower.strip())
        is_generic = any(phrase in body_lower for phrase in REVIEW_IGNORE_PHRASES)

        if has_body and not is_generic:
            return "REVIEW"

        return None

    def _inject_victim_session(self, headers):
        if not self._victim_headers:
            return headers

        victim_map = {}
        for name, line in self._victim_headers:
            victim_map[name] = line

        new_headers    = [str(headers[0])]
        replaced_names = set()

        for i in range(1, len(headers)):
            h    = str(headers[i])
            name = h.split(':', 1)[0].strip().lower() if ':' in h else ""
            if name in victim_map:
                new_headers.append(victim_map[name])
                replaced_names.add(name)
            else:
                new_headers.append(h)

        for name, line in self._victim_headers:
            if name not in replaced_names:
                new_headers.append(line)

        return new_headers

    def _play_beep(self):
        try:
            sample_rate  = 44100.0
            frequency    = 880.0
            duration_ms  = 220
            num_samples  = int(sample_rate * duration_ms / 1000)
            fmt          = AudioFormat(sample_rate, 8, 1, True, True)
            info         = DataLine.Info(SourceDataLine, fmt)
            line         = AudioSystem.getLine(info)
            line.open(fmt)
            line.start()
            import jarray
            buf = jarray.array(
                [int(127 * math.sin(2 * math.pi * frequency * i / sample_rate)) & 0xFF
                 for i in range(num_samples)],
                'b'
            )
            line.write(buf, 0, len(buf))
            line.drain()
            line.close()
        except Exception:
            Toolkit.getDefaultToolkit().beep()

    def _build_ui(self):
        self._main_panel = JPanel(BorderLayout())
        self._main_panel.setBackground(COLOR_BG)

        UIManager.put("TabbedPane.background",        COLOR_SURFACE)
        UIManager.put("TabbedPane.foreground",        COLOR_TEXT)
        UIManager.put("TabbedPane.selected",          COLOR_SURFACE2)
        UIManager.put("TabbedPane.tabAreaBackground", COLOR_BG)
        UIManager.put("TabbedPane.contentAreaColor",  COLOR_SURFACE)
        UIManager.put("TabbedPane.shadow",            COLOR_BORDER)
        UIManager.put("TabbedPane.darkShadow",        COLOR_BG)
        UIManager.put("TabbedPane.highlight",         COLOR_SURFACE2)
        UIManager.put("TabbedPane.light",             COLOR_BORDER)
        UIManager.put("TabbedPane.focus",             COLOR_ACCENT)

        tabs = JTabbedPane()
        tabs.setBackground(COLOR_SURFACE)
        tabs.setForeground(COLOR_TEXT)
        tabs.setFont(FALLBACK_UI_B)

        cols = ["Method", "Path / Endpoint", "Status"]

        self._vuln_model, self._vuln_table = self._make_model_and_table(
            cols, self._vuln_details, COLOR_VULN, COLOR_VULN_DIM
        )
        vuln_req_ed, vuln_resp_ed = self._make_editor_pair('vuln')
        self._vuln_req_editor  = vuln_req_ed
        self._vuln_resp_editor = vuln_resp_ed
        self._wire_selection(
            self._vuln_table, self._vuln_details,
            vuln_req_ed, vuln_resp_ed, '_vuln_current'
        )
        vuln_panel = self._make_verdict_tab(
            self._vuln_table, vuln_req_ed, vuln_resp_ed,
            "Modified Request", "Response"
        )

        self._safe_model, self._safe_table = self._make_model_and_table(
            cols, self._safe_details, COLOR_SAFE, COLOR_SAFE_DIM
        )
        safe_req_ed, safe_resp_ed = self._make_editor_pair('safe')
        self._safe_req_editor  = safe_req_ed
        self._safe_resp_editor = safe_resp_ed
        self._wire_selection(
            self._safe_table, self._safe_details,
            safe_req_ed, safe_resp_ed, '_safe_current'
        )
        safe_panel = self._make_verdict_tab(
            self._safe_table, safe_req_ed, safe_resp_ed,
            "Modified Request", "Response"
        )

        self._review_model, self._review_table = self._make_model_and_table(
            cols, self._review_details, COLOR_REVIEW, COLOR_REVIEW_DIM
        )
        review_req_ed, review_resp_ed = self._make_editor_pair('review')
        self._review_req_editor  = review_req_ed
        self._review_resp_editor = review_resp_ed
        self._wire_selection(
            self._review_table, self._review_details,
            review_req_ed, review_resp_ed, '_review_current'
        )
        review_panel = self._make_verdict_tab(
            self._review_table, review_req_ed, review_resp_ed,
            "Modified Request", "Response"
        )

        self._vuln_tab_label   = JLabel(" [!] Vulnerable (0)")
        self._safe_tab_label   = JLabel(" [+] Secure (0)")
        self._review_tab_label = JLabel(" [?] Suspicious (0)")
        self._config_tab_label = JLabel(" Config")

        for lbl in (self._vuln_tab_label, self._safe_tab_label,
                    self._review_tab_label, self._config_tab_label):
            lbl.setFont(FALLBACK_UI_B)
            lbl.setBorder(EmptyBorder(4, 2, 4, 6))

        tabs.addTab(None, vuln_panel)
        tabs.setTabComponentAt(0, self._vuln_tab_label)
        tabs.addTab(None, safe_panel)
        tabs.setTabComponentAt(1, self._safe_tab_label)
        tabs.addTab(None, review_panel)
        tabs.setTabComponentAt(2, self._review_tab_label)

        config_panel = self._build_config_tab()
        tabs.addTab(None, config_panel)
        tabs.setTabComponentAt(3, self._config_tab_label)

        label_configs = [
            (self._vuln_tab_label,   COLOR_VULN),
            (self._safe_tab_label,   COLOR_SAFE),
            (self._review_tab_label, COLOR_REVIEW),
            (self._config_tab_label, COLOR_ACCENT),
        ]
        tab_listener = TabChangeListener(tabs, label_configs)
        tabs.addChangeListener(tab_listener)
        tab_listener.stateChanged(None)

        status_bar = self._build_status_bar()
        self._main_panel.add(tabs,       BorderLayout.CENTER)
        self._main_panel.add(status_bar, BorderLayout.SOUTH)

    def _build_config_tab(self):
        panel = JPanel(GridBagLayout())
        panel.setBackground(COLOR_BG)
        panel.setBorder(EmptyBorder(20, 24, 20, 24))

        gbc         = GridBagConstraints()
        gbc.insets  = Insets(6, 0, 6, 0)
        gbc.anchor  = GridBagConstraints.WEST
        gbc.fill    = GridBagConstraints.HORIZONTAL
        gbc.weightx = 1.0

        title_lbl = JLabel("Victim Session Configuration")
        title_lbl.setFont(Font("SansSerif", Font.BOLD, 16))
        title_lbl.setForeground(COLOR_TEXT)
        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 2
        panel.add(title_lbl, gbc)

        gbc.gridy = 1
        panel.add(JLabel(" "), gbc)

        self._session_area = JTextArea(6, 60)
        self._session_area.setFont(FALLBACK_MONO)
        self._session_area.setBackground(COLOR_SURFACE2)
        self._session_area.setForeground(COLOR_TEXT)
        self._session_area.setCaretColor(COLOR_ACCENT)
        self._session_area.setLineWrap(True)
        self._session_area.setSelectionColor(COLOR_ACCENT)

        session_scroll = JScrollPane(self._session_area)
        session_scroll.setBorder(CompoundBorder(
            MatteBorder(1, 1, 1, 1, COLOR_BORDER),
            EmptyBorder(6, 8, 6, 8)
        ))

        gbc.gridy   = 3
        gbc.weighty = 0.4
        gbc.fill    = GridBagConstraints.BOTH
        panel.add(session_scroll, gbc)

        btn_row = JPanel(FlowLayout(FlowLayout.LEFT, 10, 0))
        btn_row.setBackground(COLOR_BG)

        save_btn = PillButton("Save", COLOR_SURFACE2, COLOR_TEXT)
        save_btn.addActionListener(lambda e: self._save_config())

        self._enable_btn = PillButton("Enable", COLOR_SAFE_DIM, COLOR_SAFE)
        self._enable_btn.addActionListener(lambda e: self._toggle_enabled())

        clear_btn = PillButton("Clear All", COLOR_SURFACE2, COLOR_TEXT)
        clear_btn.addActionListener(lambda e: self._clear_results())

        self._status_pill = JLabel("  DISABLED  ")
        self._status_pill.setFont(FALLBACK_UI_B)
        self._status_pill.setForeground(COLOR_TEXT_DIM)
        self._status_pill.setOpaque(True)
        self._status_pill.setBackground(COLOR_SURFACE2)
        self._status_pill.setBorder(EmptyBorder(4, 10, 4, 10))

        btn_row.add(save_btn)
        btn_row.add(self._enable_btn)
        btn_row.add(clear_btn)
        btn_row.add(Box.createHorizontalStrut(10))
        btn_row.add(self._status_pill)

        gbc.gridy   = 4
        gbc.weighty = 0
        gbc.fill    = GridBagConstraints.HORIZONTAL
        gbc.insets  = Insets(12, 0, 6, 0)
        panel.add(btn_row, gbc)

        filler = JPanel()
        filler.setBackground(COLOR_BG)
        gbc.gridy   = 5
        gbc.weighty = 1.0
        gbc.fill    = GridBagConstraints.BOTH
        panel.add(filler, gbc)

        return panel

    def _build_status_bar(self):
        bar = JPanel(FlowLayout(FlowLayout.LEFT, 16, 4))
        bar.setBackground(COLOR_SURFACE2)
        bar.setBorder(MatteBorder(1, 0, 0, 0, COLOR_BORDER))

        brand = JLabel("BAC-TESTER")
        brand.setFont(FALLBACK_UI_B)
        brand.setForeground(COLOR_ACCENT)

        sep = JLabel(" | ")
        sep.setForeground(COLOR_BORDER)

        self._stats_label = JLabel("  Tested: 0   Vulns: 0")
        self._stats_label.setFont(FALLBACK_SMALL)
        self._stats_label.setForeground(COLOR_TEXT_DIM)

        bar.add(brand)
        bar.add(sep)
        bar.add(self._stats_label)

        return bar

    def _make_model_and_table(self, cols, details_list, row_color, dim_color):
        model = ReadOnlyTableModel(cols, 0)
        table = StyledTable(model, row_color, dim_color)
        table.setRowHeight(26)
        table.setShowGrid(False)
        table.setIntercellSpacing(Dimension(0, 0))
        table.setBackground(COLOR_SURFACE)
        table.setForeground(COLOR_TEXT)
        table.setSelectionBackground(row_color)
        table.setSelectionForeground(Color.WHITE)
        table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN)
        table.setFillsViewportHeight(True)

        header = table.getTableHeader()
        header.setBackground(COLOR_SURFACE2)
        header.setForeground(COLOR_TEXT_DIM)
        header.setFont(FALLBACK_UI_B)
        header.setBorder(MatteBorder(0, 0, 1, 0, COLOR_BORDER))

        col_model = table.getColumnModel()
        col_model.getColumn(0).setMaxWidth(80)
        col_model.getColumn(0).setMinWidth(70)
        col_model.getColumn(2).setMaxWidth(80)
        col_model.getColumn(2).setMinWidth(60)

        popup = JPopupMenu()
        popup.setBackground(COLOR_SURFACE2)
        popup.setBorder(MatteBorder(1, 1, 1, 1, COLOR_BORDER))

        repeater_item = JMenuItem("Send to Repeater")
        repeater_item.setFont(FALLBACK_UI)
        repeater_item.setBackground(COLOR_SURFACE2)
        repeater_item.setForeground(COLOR_TEXT)
        repeater_item.setOpaque(True)
        repeater_item.addActionListener(
            lambda e, t=table, d=details_list: self._send_to_repeater(t, d)
        )
        popup.add(repeater_item)

        class TableMouseListener(MouseAdapter):
            def __init__(self, tbl, pop):
                self._tbl = tbl
                self._pop = pop
            def mousePressed(self, e):
                self._maybe_show(e)
            def mouseReleased(self, e):
                self._maybe_show(e)
            def _maybe_show(self, e):
                if e.isPopupTrigger():
                    row = self._tbl.rowAtPoint(e.getPoint())
                    if row >= 0:
                        self._tbl.setRowSelectionInterval(row, row)
                    self._pop.show(e.getComponent(), e.getX(), e.getY())

        table.addMouseListener(TableMouseListener(table, popup))
        return model, table

    def _make_editor_pair(self, lc):
        ext = self

        class Controller(IMessageEditorController):
            def getHttpService(self):
                return getattr(ext, "_{}_current".format(lc), {}).get('service')
            def getRequest(self):
                return getattr(ext, "_{}_current".format(lc), {}).get('modified_req_bytes')
            def getResponse(self):
                return getattr(ext, "_{}_current".format(lc), {}).get('response_bytes')

        req_ed  = self._callbacks.createMessageEditor(Controller(), True)
        resp_ed = self._callbacks.createMessageEditor(Controller(), False)
        return req_ed, resp_ed

    def _wire_selection(self, table, details_list, req_ed, resp_ed, current_attr):
        def on_select(_table=table, _details=details_list,
                      _req=req_ed, _resp=resp_ed, _attr=current_attr):
            row = _table.getSelectedRow()
            if row < 0 or row >= len(_details):
                return
            detail = _details[row]
            setattr(self, _attr, detail)
            req_b  = detail.get('modified_req_bytes')
            resp_b = detail.get('response_bytes')
            if req_b:
                _req.setMessage(req_b, True)
            if resp_b:
                _resp.setMessage(resp_b, False)

        table.getSelectionModel().addListSelectionListener(
            lambda e, fn=on_select: fn()
        )

    def _make_verdict_tab(self, table, req_ed, resp_ed, req_title, resp_title):
        req_panel  = JPanel(BorderLayout())
        resp_panel = JPanel(BorderLayout())

        for p, title in ((req_panel, req_title), (resp_panel, resp_title)):
            p.setBackground(COLOR_SURFACE)
            header = JLabel("  " + title)
            header.setFont(FALLBACK_UI_B)
            header.setForeground(COLOR_TEXT_DIM)
            header.setOpaque(True)
            header.setBackground(COLOR_SURFACE2)
            header.setBorder(CompoundBorder(
                MatteBorder(0, 0, 1, 0, COLOR_BORDER),
                EmptyBorder(6, 8, 6, 8)
            ))
            p.add(header, BorderLayout.NORTH)

        req_panel.add(req_ed.getComponent(),   BorderLayout.CENTER)
        resp_panel.add(resp_ed.getComponent(), BorderLayout.CENTER)

        detail_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, req_panel, resp_panel)
        detail_split.setResizeWeight(0.5)
        detail_split.setDividerSize(4)

        table_scroll = JScrollPane(table)
        table_scroll.setBackground(COLOR_SURFACE)
        table_scroll.getViewport().setBackground(COLOR_SURFACE)
        table_scroll.setBorder(MatteBorder(0, 0, 1, 0, COLOR_BORDER))

        main_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, table_scroll, detail_split)
        main_split.setResizeWeight(0.5)
        main_split.setDividerSize(4)

        panel = JPanel(BorderLayout())
        panel.setBackground(COLOR_SURFACE)
        panel.add(main_split, BorderLayout.CENTER)
        return panel

    def _toggle_enabled(self):
        self._enabled = not self._enabled
        if self._enabled:
            self._save_config()
            if not self._victim_headers:
                self._enabled = False
                self._status_pill.setText("  NO SESSION  ")
                self._status_pill.setForeground(COLOR_REVIEW)
                self._status_pill.setBackground(COLOR_REVIEW_DIM)
                return
            self._enable_btn.setText("Disable")
            self._enable_btn.setBackground(COLOR_VULN_DIM)
            self._enable_btn.setForeground(COLOR_VULN)
            self._status_pill.setText("  ENABLED  ")
            self._status_pill.setForeground(COLOR_SAFE)
            self._status_pill.setBackground(COLOR_SAFE_DIM)
        else:
            self._enable_btn.setText("Enable")
            self._enable_btn.setBackground(COLOR_SAFE_DIM)
            self._enable_btn.setForeground(COLOR_SAFE)
            self._status_pill.setText("  DISABLED  ")
            self._status_pill.setForeground(COLOR_TEXT_DIM)
            self._status_pill.setBackground(COLOR_SURFACE2)

    def _save_config(self):
        raw = self._session_area.getText().strip()
        self._victim_headers = []
        for line in raw.splitlines():
            line = line.strip()
            if line and ':' in line:
                name = line.split(':', 1)[0].strip().lower()
                self._victim_headers.append((name, line))
        self._victim_header = raw

    def _clear_results(self):
        self._request_count = 0
        self._vuln_count    = 0
        self._stats_label.setText("  Tested: 0   Vulns: 0")
        for lc in ('vuln', 'safe', 'review'):
            getattr(self, "_{}_model".format(lc)).setRowCount(0)
            getattr(self, "_{}_details".format(lc))[:] = []
            setattr(self, "_{}_current".format(lc), {})
            empty = self._helpers.stringToBytes("")
            getattr(self, "_{}_req_editor".format(lc)).setMessage(empty, True)
            getattr(self, "_{}_resp_editor".format(lc)).setMessage(empty, False)
        self._vuln_tab_label.setText(" [!] Vulnerable (0)")
        self._safe_tab_label.setText(" [+] Secure (0)")
        self._review_tab_label.setText(" [?] Suspicious (0)")

    def _send_to_repeater(self, table, details_list):
        row = table.getSelectedRow()
        if row < 0 or row >= len(details_list):
            return
        detail  = details_list[row]
        service = detail.get('service')
        req_b   = detail.get('modified_req_bytes')
        if service and req_b:
            use_https = service.getProtocol().lower() == 'https'
            self._callbacks.sendToRepeater(
                service.getHost(),
                service.getPort(),
                use_https,
                req_b,
                "BAC-TESTER"
            )
