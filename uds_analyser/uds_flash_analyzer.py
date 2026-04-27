"""
uds_flash_analyzer.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
UDS Flash Log Analyzer & RCA Report Generator
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Supports log formats:
  • Vector CANalyzer / CANoe (.asc)
  • BusMaster (.log)
  • CSV / generic text logs
  • Peak PCAN Viewer (.trc)

Features:
  • Drag-and-drop or Browse to open CAN log
  • Parses all UDS services (ISO 14229-1)
  • Detects 30+ UDS flashing issues automatically
  • Timeline view of request / response pairs
  • Colour-coded issue severity (CRITICAL / ERROR / WARNING / INFO)
  • Generates full RCA PDF report with corrective & preventive actions

Run:   python uds_flash_analyzer.py
Deps:  pip install PyQt6 reportlab
"""

from __future__ import annotations
import sys, os, re, time, csv
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from datetime import datetime
from collections import defaultdict

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QFileDialog, QTableWidget, QTableWidgetItem,
    QHeaderView, QSplitter, QTextEdit, QTabWidget, QFrame, QLineEdit,
    QComboBox, QProgressBar, QScrollArea, QCheckBox, QGroupBox,
    QGridLayout, QListWidget, QListWidgetItem, QMessageBox, QSizePolicy,
)
from PyQt6.QtCore import (
    Qt, QThread, pyqtSignal, QTimer, QMimeData, QUrl,
)
from PyQt6.QtGui import (
    QColor, QBrush, QFont, QPalette, QDragEnterEvent, QDropEvent,
)

# ─── ReportLab ────────────────────────────────────────────────────────────────
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm, cm
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, KeepTogether,
)
from reportlab.platypus.flowables import HRFlowable

# ═══════════════════════════════════════════════════════════════════════════════
# COLOUR PALETTE
# ═══════════════════════════════════════════════════════════════════════════════
C = {
    "bg":       "#0d1117", "bg2": "#161b22", "bg3": "#21262d", "bg4": "#2d333b",
    "border":   "#30363d", "text": "#e6edf3", "text2": "#8b949e", "text3": "#656d76",
    "cyan":     "#39c5cf", "green": "#3fb950", "green_d": "#2ea043",
    "red":      "#f85149", "red_d": "#da3633", "amber": "#e3b341",
    "purple":   "#a371f7", "accent": "#388bfd", "accent_d": "#1f6feb",
    "orange":   "#fb8f44",
}

SS = f"""
QWidget{{background:{C['bg']};color:{C['text']};
    font-family:Consolas,"Cascadia Code",monospace;font-size:11px;}}
QMainWindow{{background:{C['bg']};}}
QTabWidget::pane{{border:1px solid {C['border']};background:{C['bg']};}}
QTabBar::tab{{background:{C['bg2']};color:{C['text2']};padding:6px 18px;
    border:none;border-bottom:2px solid transparent;
    font-family:-apple-system,sans-serif;font-size:11px;}}
QTabBar::tab:selected{{color:{C['cyan']};border-bottom:2px solid {C['cyan']};background:{C['bg']};}}
QTabBar::tab:hover{{background:{C['bg3']};color:{C['text']};}}
QTableWidget{{background:{C['bg']};gridline-color:#1c2128;border:none;
    alternate-background-color:{C['bg2']};
    selection-background-color:{C['bg3']};selection-color:{C['text']};}}
QTableWidget::item{{padding:3px 8px;border:none;}}
QHeaderView::section{{background:{C['bg3']};color:{C['text2']};padding:5px 8px;
    border:none;border-bottom:1px solid {C['border']};
    font-size:10px;text-transform:uppercase;letter-spacing:0.5px;}}
QPushButton{{background:{C['bg3']};color:{C['text2']};border:1px solid {C['border']};
    border-radius:4px;padding:5px 14px;
    font-family:-apple-system,sans-serif;font-size:11px;}}
QPushButton:hover{{background:{C['bg4']};color:{C['text']};border-color:#444c56;}}
QPushButton#btn_primary{{background:{C['accent_d']};color:#fff;border-color:{C['accent']};}}
QPushButton#btn_primary:hover{{background:#2979ff;}}
QPushButton#btn_green{{background:{C['green_d']};color:#fff;border-color:{C['green']};}}
QPushButton#btn_green:hover{{background:#3c8e47;}}
QPushButton#btn_red{{background:{C['red_d']};color:#fff;border-color:{C['red']};}}
QLineEdit,QComboBox{{background:{C['bg3']};color:{C['text']};
    border:1px solid {C['border']};border-radius:4px;padding:4px 8px;font-size:11px;}}
QLineEdit:focus,QComboBox:focus{{border-color:{C['accent']};}}
QComboBox QAbstractItemView{{background:{C['bg3']};color:{C['text']};
    selection-background-color:{C['bg4']};border:1px solid {C['border']};}}
QScrollBar:vertical{{background:{C['bg']};width:6px;border:none;}}
QScrollBar::handle:vertical{{background:{C['bg4']};border-radius:3px;min-height:20px;}}
QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical{{height:0;}}
QScrollBar:horizontal{{background:{C['bg']};height:6px;border:none;}}
QScrollBar::handle:horizontal{{background:{C['bg4']};border-radius:3px;}}
QSplitter::handle{{background:{C['border']};}}
QGroupBox{{color:{C['text2']};border:1px solid {C['border']};border-radius:6px;
    margin-top:14px;padding-top:8px;font-size:10px;text-transform:uppercase;}}
QGroupBox::title{{subcontrol-origin:margin;left:8px;top:2px;color:{C['text3']};}}
QTextEdit{{background:{C['bg2']};color:{C['text']};border:1px solid {C['border']};
    border-radius:4px;font-family:Consolas,monospace;font-size:11px;}}
QProgressBar{{background:{C['bg3']};border:1px solid {C['border']};border-radius:3px;
    text-align:center;color:{C['text']};}}
QProgressBar::chunk{{background:{C['accent']};border-radius:2px;}}
QCheckBox{{color:{C['text2']};spacing:5px;}}
QCheckBox::indicator{{width:13px;height:13px;background:{C['bg3']};
    border:1px solid {C['border']};border-radius:3px;}}
QCheckBox::indicator:checked{{background:{C['accent']};border-color:{C['accent']};}}
QListWidget{{background:{C['bg2']};border:1px solid {C['border']};color:{C['text']};}}
QListWidget::item{{padding:4px 8px;}}
QListWidget::item:selected{{background:{C['bg4']};color:{C['cyan']};}}
QLabel{{color:{C['text']};}}
"""

# ═══════════════════════════════════════════════════════════════════════════════
# UDS SERVICE DEFINITIONS  (ISO 14229-1)
# ═══════════════════════════════════════════════════════════════════════════════
UDS_SERVICES = {
    0x10: "DiagnosticSessionControl",
    0x11: "ECUReset",
    0x14: "ClearDiagnosticInformation",
    0x19: "ReadDTCInformation",
    0x22: "ReadDataByIdentifier",
    0x23: "ReadMemoryByAddress",
    0x27: "SecurityAccess",
    0x28: "CommunicationControl",
    0x29: "Authentication",
    0x2A: "ReadDataByPeriodicIdentifier",
    0x2C: "DynamicallyDefineDataIdentifier",
    0x2E: "WriteDataByIdentifier",
    0x2F: "InputOutputControlByIdentifier",
    0x31: "RoutineControl",
    0x34: "RequestDownload",
    0x35: "RequestUpload",
    0x36: "TransferData",
    0x37: "RequestTransferExit",
    0x38: "RequestFileTransfer",
    0x3D: "WriteMemoryByAddress",
    0x3E: "TesterPresent",
    0x83: "AccessTimingParameter",
    0x84: "SecuredDataTransmission",
    0x85: "ControlDTCSetting",
    0x86: "ResponseOnEvent",
    0x87: "LinkControl",
}

UDS_SESSION_TYPES = {
    0x01: "defaultSession",
    0x02: "programmingSession",
    0x03: "extendedDiagnosticSession",
    0x04: "safetySystemDiagnosticSession",
    0x60: "OBDIIDiagnosticSession",
}

UDS_NRC = {
    0x10: "generalReject",
    0x11: "serviceNotSupported",
    0x12: "subFunctionNotSupported",
    0x13: "incorrectMessageLengthOrInvalidFormat",
    0x14: "responseTooLong",
    0x21: "busyRepeatRequest",
    0x22: "conditionsNotCorrect",
    0x24: "requestSequenceError",
    0x25: "noResponseFromSubnetComponent",
    0x26: "failurePreventsExecutionOfRequestedAction",
    0x31: "requestOutOfRange",
    0x33: "securityAccessDenied",
    0x35: "invalidKey",
    0x36: "exceededNumberOfAttempts",
    0x37: "requiredTimeDelayNotExpired",
    0x38: "SecureDataVerificationFailed",
    0x70: "uploadDownloadNotAccepted",
    0x71: "transferDataSuspended",
    0x72: "generalProgrammingFailure",
    0x73: "wrongBlockSequenceCounter",
    0x78: "requestCorrectlyReceivedResponsePending",
    0x7E: "subFunctionNotSupportedInActiveSession",
    0x7F: "serviceNotSupportedInActiveSession",
}

UDS_ROUTINE_IDS = {
    0xFF00: "EraseMemory",
    0xFF01: "CheckProgrammingDependencies",
    0xFF02: "EraseMirrorMemoryDTCs",
    0x0202: "CheckMemory",
    0x0203: "CheckApplicationSoftware",
    0x0204: "CheckApplicationData",
    0x0205: "CheckBootSoftware",
    0x0206: "FinalizeApplication",
    0xF003: "FlashDriverInit",
    0x0301: "ActivateSoftware",
}

# ═══════════════════════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════════
SEVERITY_ORDER  = {"CRITICAL": 0, "ERROR": 1, "WARNING": 2, "INFO": 3}
SEVERITY_COLORS = {
    "CRITICAL": "#f85149",
    "ERROR":    "#fb8f44",
    "WARNING":  "#e3b341",
    "INFO":     "#39c5cf",
}


@dataclass
class CANMsg:
    timestamp:  float
    msg_id:     int
    data:       bytes
    channel:    int  = 1
    direction:  str  = "Rx"
    line_no:    int  = 0

    @property
    def id_str(self) -> str:
        return f"{self.msg_id:03X}" if self.msg_id <= 0x7FF else f"{self.msg_id:08X}"

    @property
    def data_hex(self) -> str:
        return " ".join(f"{b:02X}" for b in self.data)


@dataclass
class UDSFrame:
    timestamp:   float
    src_id:      int
    dst_id:      int
    service_id:  int
    sub_func:    Optional[int]
    data:        bytes
    raw_can:     List[CANMsg]
    is_response: bool
    is_nrc:      bool      = False
    nrc_code:    int       = 0
    is_pending:  bool      = False
    line_no:     int       = 0

    @property
    def service_name(self) -> str:
        sid = self.service_id & 0xBF   # strip response bit
        return UDS_SERVICES.get(sid, f"SID_0x{sid:02X}")

    @property
    def nrc_str(self) -> str:
        return UDS_NRC.get(self.nrc_code, f"NRC_0x{self.nrc_code:02X}")

    @property
    def direction_str(self) -> str:
        return "RSP" if self.is_response else "REQ"

    @property
    def id_str(self) -> str:
        return f"{self.src_id:03X}" if self.src_id <= 0x7FF else f"{self.src_id:08X}"


@dataclass
class FlashSequence:
    """One complete UDS flash attempt extracted from log."""
    session_start:       Optional[float]    = None
    session_end:         Optional[float]    = None
    programming_session: bool               = False
    security_access_ok:  bool               = False
    erase_ok:            bool               = False
    download_requested:  bool               = False
    transfer_frames:     int                = 0
    transfer_exit_ok:    bool               = False
    check_ok:            bool               = False
    frames:              List[UDSFrame]     = field(default_factory=list)
    ecu_address:         int                = 0

    @property
    def duration(self) -> float:
        if self.session_start and self.session_end:
            return self.session_end - self.session_start
        return 0.0


@dataclass
class Issue:
    severity:   str           # CRITICAL / ERROR / WARNING / INFO
    code:       str           # e.g. "UDS-001"
    title:      str
    description: str
    timestamp:  Optional[float]
    service:    str
    raw_data:   str
    root_cause: str
    corrective_action: str
    preventive_action: str
    line_no:    int = 0

    @property
    def sev_order(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 99)


# ═══════════════════════════════════════════════════════════════════════════════
# LOG PARSER  (ASC / BusMaster / CSV / TRC)
# ═══════════════════════════════════════════════════════════════════════════════
class CANLogParser:
    """
    Multi-format CAN log parser.

    Supported formats:
    ┌──────────────────────────────────────────────────────────────────────┐
    │ BusMaster 3.x (.log)  ← PRIMARY FORMAT (matches screenshot exactly) │
    │   HH:MM:SS:mmmm  Rx/Tx  Channel  0xCANID  x  DLC  B0 B1 ...        │
    │   15:44:23:5159  Rx  1  0x18DA3DF1  x  8  02 10 02 ...              │
    │                                                                      │
    │ Vector ASC (.asc)                                                    │
    │   timestamp  channel  CANID  Rx/Tx  d  dlc  B0 B1 ...               │
    │                                                                      │
    │ PCAN Viewer TRC (.trc)                                               │
    │   N)  ts  DT  CANID  DLC  B0 B1 ...                                 │
    │                                                                      │
    │ Generic CSV / plain text                                             │
    └──────────────────────────────────────────────────────────────────────┘
    """

    @staticmethod
    def detect_format(path: str) -> str:
        ext = os.path.splitext(path)[1].lower()
        try:
            with open(path, "r", encoding="latin-1", errors="replace") as f:
                head = "".join(f.readline() for _ in range(10))
            head_low = head.lower()
        except Exception:
            head_low = ""

        if "busmaster" in head_low or "***" in head_low:
            return "bm"
        if ext == ".asc" or ("date" in head_low and "base" in head_low):
            return "asc"
        if ext == ".trc" or (";   " in head_low and "msg" in head_low):
            return "trc"
        if ext == ".log":
            return "bm"
        if ext in (".csv", ".txt"):
            return "csv"
        return "bm"

    @classmethod
    def parse(cls, path: str) -> Tuple[List[CANMsg], List[str]]:
        fmt      = cls.detect_format(path)
        msgs     : List[CANMsg] = []
        warnings : List[str]   = []
        try:
            with open(path, "r", encoding="latin-1", errors="replace") as f:
                lines = f.readlines()
        except Exception as e:
            return [], [f"Cannot open file: {e}"]

        parsers = {
            "bm":  cls._parse_bm,
            "asc": cls._parse_asc,
            "trc": cls._parse_trc,
            "csv": cls._parse_csv,
        }
        # Try primary format first, then fall back
        order = [fmt] + [k for k in parsers if k != fmt]
        for try_fmt in order:
            try:
                m, w = parsers[try_fmt](lines)
                if len(m) >= 5:
                    if try_fmt != fmt:
                        warnings.append(
                            f"Note: parsed as {try_fmt.upper()} format "
                            f"(detected {fmt.upper()}), found {len(m)} frames.")
                    msgs, warnings = m, w
                    break
                elif len(m) > len(msgs):
                    msgs, warnings = m, w
            except Exception as e:
                warnings.append(f"Parser {try_fmt} error: {e}")

        if not msgs:
            warnings.append(
                "No frames parsed. Check log format matches one of: "
                "BusMaster .log, Vector .asc, PCAN .trc, CSV.")
        return msgs, warnings

    # ──────────────────────────────────────────────────────────────────────────
    # BusMaster 3.x  (.log)
    #
    # EXACT FORMAT (from header line 13 in screenshot):
    #   ***<Time><Tx/Rx><Channel><CAN ID><Type><DLC><DataBytes>***
    #
    # Data lines:
    #   15:44:23:5159  Rx  1  0xC00003D   x  8  D3 FF FA E1 FF F7 FF 15
    #   15:44:23:5163  Rx  1  0x18FF463D  x  8  01 FF FF FF FF FF FF FF
    #   15:44:30:0100  Tx  1  0x18DA3DF1  x  8  02 10 02 AA AA AA AA AA
    #
    # Column index after split():
    #   [0] Time      HH:MM:SS:mmmm  (4-digit sub-second)
    #   [1] Tx/Rx     "Rx" or "Tx"
    #   [2] Channel   "1"
    #   [3] CAN ID    "0xC00003D" or "0x18FF463D"  (with 0x prefix, 29-bit ext)
    #   [4] Type      "x" (extended) or "s" (standard)
    #   [5] DLC       "8"
    #   [6..13] Data  "D3 FF FA E1 FF F7 FF 15"
    #
    # Timestamp conversion:
    #   15:44:23:5159 -> 15*3600 + 44*60 + 23 + 5159/10000
    #   (4th field is 10ths of ms, i.e. 0.1ms resolution)
    # ──────────────────────────────────────────────────────────────────────────
    @classmethod
    def _parse_bm(cls, lines: List[str]) -> Tuple[List[CANMsg], List[str]]:
        msgs  : List[CANMsg] = []
        warns : List[str]    = []
        col_order_known = False   # once we see a data line, lock in column order
        use_new_format  = True    # BusMaster 3.x: Time Dir Chan ID Type DLC Data

        for lno, raw in enumerate(lines, 1):
            line = raw.strip()
            if not line:
                continue
            # Skip BusMaster header lines
            if line.startswith("***"):
                # Check column header to confirm format
                if "<Time>" in line and "<Tx/Rx>" in line and "<CAN ID>" in line:
                    use_new_format = True
                    col_order_known = True
                continue
            if line.lower().startswith(("start", "end", "//", "#")):
                continue

            parts = line.split()
            if len(parts) < 6:
                continue

            # ── Parse timestamp ───────────────────────────────────────────────
            ts = cls._parse_bm_timestamp(parts[0])
            if ts is None:
                continue

            # ── BusMaster 3.x: Dir Chan ID Type DLC Data ─────────────────────
            # Try format: ts dir chan id type dlc data
            # Detect by checking if parts[1] is Rx/Tx and parts[3] starts with 0x
            if (len(parts) >= 6 and
                    parts[1].lower() in ("rx", "tx") and
                    (parts[3].lower().startswith("0x") or
                     re.match(r'^[0-9A-Fa-f]{5,8}$', parts[3]))):
                # Confirmed BusMaster 3.x format
                dirn = parts[1]
                try:
                    chan = int(parts[2])
                except ValueError:
                    chan = 1
                id_tok = parts[3].lower().lstrip("0x") or "0"
                try:
                    mid = int(id_tok, 16)
                except ValueError:
                    continue
                # parts[4] = type ('x'=extended, 's'=standard, 'r'=remote)
                # parts[5] = DLC
                try:
                    dlc = int(parts[5])
                except (ValueError, IndexError):
                    continue
                if not (0 <= dlc <= 64):
                    continue
                data_parts = parts[6: 6 + dlc]
                try:
                    data = bytes(int(b, 16) for b in data_parts
                                 if re.match(r'^[0-9A-Fa-f]{1,2}$', b))
                except ValueError:
                    data = b''
                msgs.append(CANMsg(ts, mid, data, chan, dirn, lno))
                continue

            # ── BusMaster 2.x / older: ts chan id dir type dlc data ──────────
            # 00:15:36:679  1  0x7E0  Rx  d  8  02 10 02 ...
            if (len(parts) >= 7 and
                    (parts[2].lower().startswith("0x") or
                     re.match(r'^[0-9A-Fa-f]{1,8}$', parts[2].lstrip("0x")))):
                try:
                    chan = int(parts[1]) if parts[1].isdigit() else 1
                except ValueError:
                    chan = 1
                id_tok = parts[2].lower().lstrip("0x") or "0"
                try:
                    mid = int(id_tok, 16)
                except ValueError:
                    continue
                dirn = parts[3] if parts[3] in ("Rx", "Tx", "rx", "tx") else "Rx"
                try:
                    dlc = int(parts[5])
                except (ValueError, IndexError):
                    try:
                        dlc = int(parts[4])
                        data_parts = parts[5: 5 + dlc]
                    except (ValueError, IndexError):
                        continue
                    else:
                        try:
                            data = bytes(int(b, 16) for b in data_parts
                                         if re.match(r'^[0-9A-Fa-f]{1,2}$', b))
                        except ValueError:
                            data = b''
                        msgs.append(CANMsg(ts, mid, data, chan, dirn, lno))
                        continue
                data_parts = parts[6: 6 + dlc]
                try:
                    data = bytes(int(b, 16) for b in data_parts
                                 if re.match(r'^[0-9A-Fa-f]{1,2}$', b))
                except ValueError:
                    data = b''
                msgs.append(CANMsg(ts, mid, data, chan, dirn, lno))

        return msgs, warns

    @staticmethod
    def _parse_bm_timestamp(tok: str) -> Optional[float]:
        """
        Convert BusMaster timestamp token to float seconds.

        Formats seen:
          15:44:23:5159   HH:MM:SS:tttt  (tttt = 0.1ms ticks = /10000)
          00:00:01:234    HH:MM:SS:mmm   (mmm  = milliseconds = /1000)
          56679.209       plain float (seconds)
          56679209        plain integer (milliseconds)
        """
        if not tok:
            return None
        # Plain float
        if "." in tok and ":" not in tok:
            try:
                return float(tok)
            except ValueError:
                return None
        # Plain integer (ms from session start)
        if tok.isdigit():
            try:
                v = int(tok)
                return v / 1000.0 if v > 100000 else float(v)
            except ValueError:
                return None
        # Colon-separated
        if ":" in tok:
            parts = tok.replace(".", ":").split(":")
            try:
                if len(parts) == 4:
                    h, m, s, sub = int(parts[0]), int(parts[1]), int(parts[2]), int(parts[3])
                    # Determine sub-second resolution:
                    # BusMaster 3.x uses 4 digits (0.1ms resolution) -> /10000
                    # BusMaster 2.x uses 3 digits (ms) -> /1000
                    # BusMaster 2.x also uses 3 digits with value 0-999
                    divisor = 10000 if len(parts[3]) == 4 else 1000
                    return h * 3600 + m * 60 + s + sub / divisor
                elif len(parts) == 3:
                    h, m, s_f = int(parts[0]), int(parts[1]), float(parts[2])
                    return h * 3600 + m * 60 + s_f
            except (ValueError, IndexError):
                pass
        return None

    # ──────────────────────────────────────────────────────────────────────────
    # Vector ASC (.asc)
    # 0.123456 1  18DA3DF1x  Rx d 8  02 10 02 AA AA AA AA AA
    # ──────────────────────────────────────────────────────────────────────────
    @classmethod
    def _parse_asc(cls, lines: List[str]) -> Tuple[List[CANMsg], List[str]]:
        msgs : List[CANMsg] = []
        warns: List[str]    = []
        SKIP = ("date", "base", "version", "//", "begin", "end", "#",
                "no", "start", "time", "logg")
        for lno, raw in enumerate(lines, 1):
            line = raw.strip()
            if not line or line.lower().startswith(SKIP):
                continue
            parts = line.split()
            if len(parts) < 5:
                continue
            try:
                ts = float(parts[0])
            except ValueError:
                continue
            # Find Rx/Tx anchor
            dir_pos = next((i for i, p in enumerate(parts)
                            if p.lower() in ("rx", "tx")), -1)
            if dir_pos < 1:
                continue
            # ID is token before Rx/Tx, strip trailing 'x' for extended
            id_tok = parts[dir_pos - 1].lower().rstrip("x")
            try:
                mid = int(id_tok, 16)
            except ValueError:
                continue
            chan = 1
            if dir_pos >= 2:
                try:
                    chan = int(parts[1])
                except ValueError:
                    pass
            dirn = parts[dir_pos]
            # Find 'd' marker then DLC
            rest = parts[dir_pos + 1:]
            off  = 1 if rest and rest[0].lower() in ('d', 'r', 'b') else 0
            if off >= len(rest):
                continue
            try:
                dlc = int(rest[off])
            except (ValueError, IndexError):
                continue
            data_parts = rest[off + 1: off + 1 + dlc]
            try:
                data = bytes(int(b, 16) for b in data_parts
                             if re.match(r'^[0-9A-Fa-f]{1,2}$', b))
            except ValueError:
                data = b''
            msgs.append(CANMsg(ts, mid, data, chan, dirn, lno))
        return msgs, warns

    # ──────────────────────────────────────────────────────────────────────────
    # PCAN Viewer TRC (.trc)
    # 1)  0.0001  DT  18DA3DF1  8  02 10 02 ...
    # ──────────────────────────────────────────────────────────────────────────
    @classmethod
    def _parse_trc(cls, lines: List[str]) -> Tuple[List[CANMsg], List[str]]:
        msgs : List[CANMsg] = []
        warns: List[str]    = []
        for lno, raw in enumerate(lines, 1):
            line = re.sub(r"^\s*\d+\)\s*", "", raw.strip())
            if not line or line.startswith(";"):
                continue
            parts = line.split()
            if len(parts) < 4:
                continue
            try:
                ts = float(parts[0])
            except ValueError:
                continue
            try:
                type_tok = parts[1].upper()
                dirn = "Tx" if type_tok in ("TX", "TXERR", "DT_TX") else "Rx"
                mid  = int(parts[2].lstrip("0x"), 16)
                dlc  = int(parts[3])
                data = bytes(int(b, 16) for b in parts[4: 4 + dlc]
                             if re.match(r'^[0-9A-Fa-f]{1,2}$', b))
                msgs.append(CANMsg(ts, mid, data, 1, dirn, lno))
            except Exception:
                try:
                    mid  = int(parts[1].lstrip("0x"), 16)
                    dlc  = int(parts[2])
                    data = bytes(int(b, 16) for b in parts[3: 3 + dlc]
                                 if re.match(r'^[0-9A-Fa-f]{1,2}$', b))
                    msgs.append(CANMsg(ts, mid, data, 1, "Rx", lno))
                except Exception:
                    pass
        return msgs, warns

    # ──────────────────────────────────────────────────────────────────────────
    # Generic CSV / plain text
    # ──────────────────────────────────────────────────────────────────────────
    @classmethod
    def _parse_csv(cls, lines: List[str]) -> Tuple[List[CANMsg], List[str]]:
        msgs : List[CANMsg] = []
        warns: List[str]    = []
        for lno, raw in enumerate(lines, 1):
            line = raw.strip()
            if not line or line.lower().startswith(("time", "#", "//", ";")):
                continue
            for sep in (",", ";", "\t", None):
                parts = (line.split(sep) if sep else line.split())
                parts = [p.strip() for p in parts if p.strip()]
                if len(parts) < 3:
                    continue
                try:
                    ts  = float(parts[0].replace(",", "."))
                    mid = int(parts[1].lstrip("0x"), 16)
                    try:
                        dlc = int(parts[2])
                        if 0 <= dlc <= 64:
                            data = bytes(int(b, 16) for b in parts[3: 3 + dlc]
                                         if re.match(r'^[0-9A-Fa-f]{1,2}$', b))
                            msgs.append(CANMsg(ts, mid, data, 1, "Rx", lno))
                            break
                    except ValueError:
                        pass
                    raw_hex = parts[2].replace(" ", "").replace("-", "")
                    if re.match(r'^[0-9a-fA-F]+$', raw_hex) and len(raw_hex) % 2 == 0:
                        data = bytes(int(raw_hex[i:i+2], 16)
                                     for i in range(0, len(raw_hex), 2))
                        msgs.append(CANMsg(ts, mid, data, 1, "Rx", lno))
                        break
                except Exception:
                    continue
        return msgs, warns


# ═══════════════════════════════════════════════════════════════════════════════
# ISO-TP REASSEMBLER  (ISO 15765-2)
# ═══════════════════════════════════════════════════════════════════════════════
class ISOTPReassembler:
    """
    ISO 15765-2 reassembler with SID-based request/response classification.

    KEY FIX: BusMaster (and some other loggers) record ALL frames as 'Rx'
    even for tester-transmitted frames. Therefore we CANNOT rely on the
    direction field. Instead we classify by the UDS SID byte:
      - SID 0x10-0x3E (and 0x83-0x87) = Request
      - SID 0x50-0x7E (request | 0x40) = Positive Response
      - SID 0x7F                        = Negative Response
    CAN ID still disambiguates when two different IDs are used.
    """
    def __init__(self, rx_id: int, tx_id: int):
        self.rx_id  = rx_id
        self.tx_id  = tx_id
        # Two independent reassembly streams: "req" and "resp"
        self._state: Dict[str, dict] = {
            "req":  {"buf": None, "total": 0, "seq": 0, "ts": 0.0, "first": None},
            "resp": {"buf": None, "total": 0, "seq": 0, "ts": 0.0, "first": None},
        }
        self.complete_frames: List[Tuple[float, bytes, bool, CANMsg]] = []

    @staticmethod
    def _classify_by_sid(data: bytes) -> Optional[bool]:
        """
        Return True  = response
               False = request
               None  = cannot determine (CF / FC — use previous state)
        Uses only the SID byte — direction field is IGNORED.
        """
        if not data:
            return None
        pci = data[0]
        ft  = (pci >> 4) & 0xF

        if ft == 0:   # Single Frame — SID is right after PCI
            ln = pci & 0xF
            off = 2 if ln == 0 else 1   # extended SF has extra length byte
            if off >= len(data):
                return None
            sid = data[off]
        elif ft == 1:   # First Frame
            if len(data) < 3:
                return None
            sid = data[2]
        else:
            # CF (0x2x) or FC (0x3x) — classification inherits from FF
            return None

        if sid == 0x7F:            return True   # NRC = response
        if sid & 0x40:             return True   # positive response
        if sid in UDS_REQUEST_SIDS: return False  # request
        return None   # unknown SID

    def feed(self, msg: CANMsg) -> Optional[bytes]:
        if msg.msg_id not in (self.rx_id, self.tx_id):
            return None
        if not msg.data:
            return None

        pci        = msg.data[0]
        frame_type = (pci >> 4) & 0xF

        # ── Determine request vs response ──────────────────────────────────────
        # Priority:  SID analysis  >  CAN ID  >  direction field
        is_resp = self._classify_by_sid(msg.data)

        if is_resp is None:
            # CF or FC: inherit from whichever stream has active reassembly
            if frame_type == 2:    # Consecutive Frame
                # Attach to whichever stream is currently reassembling
                if   self._state["resp"]["buf"] is not None:
                    is_resp = True
                elif self._state["req"]["buf"]  is not None:
                    is_resp = False
                else:
                    return None   # stray CF with no active FF
            elif frame_type == 3:  # Flow Control — direction is opposite of requester
                is_resp = (msg.msg_id == self.rx_id)
            else:
                # Fallback to CAN ID if SID classification failed
                is_resp = (msg.msg_id == self.rx_id)

        # Additional override: if both IDs are the same (single-ID log), use SID only
        if self.rx_id == self.tx_id:
            sid_class = self._classify_by_sid(msg.data)
            if sid_class is not None:
                is_resp = sid_class

        side = "resp" if is_resp else "req"
        st   = self._state[side]

        # ── ISO-TP frame processing ─────────────────────────────────────────────
        if frame_type == 0:                         # Single Frame
            ln = pci & 0xF
            if ln == 0:                             # extended SF (CAN FD)
                if len(msg.data) < 2:
                    return None
                ln      = msg.data[1]
                payload = bytes(msg.data[2: 2 + ln])
            else:
                payload = bytes(msg.data[1: 1 + ln])
            if not payload:
                return None
            self.complete_frames.append((msg.timestamp, payload, is_resp, msg))
            return payload

        elif frame_type == 1:                       # First Frame
            if len(msg.data) < 2:
                return None
            ln = ((pci & 0xF) << 8) | msg.data[1]
            if ln == 0 and len(msg.data) >= 6:      # CAN FD extended FF
                ln = (msg.data[2] << 24 | msg.data[3] << 16 |
                      msg.data[4] << 8  | msg.data[5])
                st["buf"] = bytearray(msg.data[6:])
            else:
                st["buf"] = bytearray(msg.data[2:])
            st["total"] = ln
            st["seq"]   = 1
            st["ts"]    = msg.timestamp
            st["first"] = msg
            return None

        elif frame_type == 2:                       # Consecutive Frame
            if st["buf"] is None:
                return None
            seq = pci & 0xF
            if seq != (st["seq"] & 0xF):
                st["buf"] = None                    # sequence error — reset
                return None
            st["buf"] += bytearray(msg.data[1:])
            st["seq"]  += 1
            if len(st["buf"]) >= st["total"]:
                payload  = bytes(st["buf"][: st["total"]])
                st["buf"] = None
                self.complete_frames.append((st["ts"], payload, is_resp, st["first"]))
                return payload

        elif frame_type == 3:                       # Flow Control — ignore
            pass

        return None


# ═══════════════════════════════════════════════════════════════════════════════
# UDS FRAME DECODER
# ═══════════════════════════════════════════════════════════════════════════════
KNOWN_ECU_PAIRS = [
    # ── Standard 11-bit UDS / OBD-II ─────────────────────────────────────────
    (0x7DF, 0x7E8), (0x7E0, 0x7E8), (0x7E1, 0x7E9),
    (0x7E2, 0x7EA), (0x7E3, 0x7EB), (0x7E4, 0x7EC),
    (0x7E5, 0x7ED), (0x7E6, 0x7EE), (0x7E7, 0x7EF),
    # ── Common proprietary 11-bit ─────────────────────────────────────────────
    (0x600, 0x608), (0x601, 0x609), (0x700, 0x708),
    (0x701, 0x709), (0x710, 0x718), (0x720, 0x728),
    # ── J1939 / ISO 15765-4 29-bit UDS (Physical addressing) ─────────────────
    # Format: 0x18DA<ECU_ADDR><TESTER_ADDR>
    # Tester=0xF1 -> these are standard J1939 UDS physical addresses
    (0x18DA00F1, 0x18DAF100), (0x18DA01F1, 0x18DAF101),
    (0x18DA02F1, 0x18DAF102), (0x18DA03F1, 0x18DAF103),
    (0x18DA0BF1, 0x18DAF10B), (0x18DA10F1, 0x18DAF110),
    (0x18DA11F1, 0x18DAF111), (0x18DA20F1, 0x18DAF120),
    (0x18DA28F1, 0x18DAF128), (0x18DA3DF1, 0x18DAF13D),
    (0x18DA40F1, 0x18DAF140), (0x18DA50F1, 0x18DAF150),
    (0x18DA3CF1, 0x18DAF13C), (0x18DA3EF1, 0x18DAF13E),
    (0x18DAF1F2, 0x18DAF2F1),
    # ── J1939 Functional addressing ───────────────────────────────────────────
    (0x18DB33F1, 0x18DAF100),  # functional broadcast
]

# All UDS request service IDs (byte 0 in payload after ISO-TP)
UDS_REQUEST_SIDS = {0x10, 0x11, 0x14, 0x19, 0x22, 0x23, 0x27,
                    0x28, 0x29, 0x2A, 0x2C, 0x2E, 0x2F, 0x31,
                    0x34, 0x35, 0x36, 0x37, 0x38, 0x3D, 0x3E,
                    0x83, 0x84, 0x85, 0x86, 0x87}
# Positive response SIDs (request + 0x40)
UDS_RESPONSE_SIDS = {s | 0x40 for s in UDS_REQUEST_SIDS}
UDS_ALL_SIDS = UDS_REQUEST_SIDS | UDS_RESPONSE_SIDS | {0x7F}


def _j1939_is_uds_addr(mid: int) -> bool:
    """
    Check if a 29-bit CAN ID is likely a J1939 UDS physical/functional address.
    J1939 UDS addresses follow:  0x18DA????  (PGN 0xDA00 = peer-to-peer)
    Also:                        0x18DB????  (PGN 0xDB00 = functional)
    """
    pgn_high = (mid >> 16) & 0xFF
    pgn_low  = (mid >> 8)  & 0xFF
    return pgn_high == 0x18 and pgn_low in (0xDA, 0xDB)


def _is_uds_payload(data: bytes) -> bool:
    """Return True if this data looks like a UDS payload (after ISO-TP unwrap)."""
    if not data:
        return False
    sid = data[0]
    if sid == 0x7F and len(data) >= 3:
        return data[2] in UDS_NRC
    return sid in UDS_ALL_SIDS


def _looks_like_isotp_uds(data: bytes) -> bool:
    """
    Check if a raw CAN frame could be carrying UDS via ISO-TP.
    Handles standard 8-byte CAN and CAN FD up to 64 bytes.
    """
    if not data or len(data) < 2:
        return False
    pci = data[0]
    frame_type = (pci >> 4) & 0xF

    if frame_type == 0:             # Single Frame
        ln = pci & 0xF
        if ln == 0:                 # extended SF (CAN FD)
            if len(data) < 2:
                return False
            ln = data[1]
            pl = data[2] if len(data) > 2 else 0
        else:
            pl = data[1] if len(data) > 1 else 0
        return bool(ln) and pl in UDS_ALL_SIDS

    elif frame_type == 1:           # First Frame
        ln = ((pci & 0xF) << 8) | (data[1] if len(data) > 1 else 0)
        if ln < 7 or ln > 4095:
            return False
        pl = data[2] if len(data) > 2 else 0
        return pl in UDS_ALL_SIDS

    elif frame_type == 2:           # Consecutive Frame
        return True

    elif frame_type == 3:           # Flow Control
        return (pci & 0xF) in (0, 1, 2)  # valid FC flags

    return False


def detect_uds_pairs(msgs: List[CANMsg]) -> List[Tuple[int, int]]:
    """
    Robust UDS ECU-pair detection.

    Works for:
    - Standard 11-bit (0x7E0/0x7E8)
    - J1939 29-bit (0x18DAxxF1 / 0x18DAF1xx)
    - Albonair / custom 29-bit proprietary
    - Single-ID logs (all traffic on one CAN ID)
    - Any unknown ID that carries recognisable ISO-TP/UDS patterns
    """
    id_set = set(m.msg_id for m in msgs)
    found : List[Tuple[int, int]] = []

    # ── Step 1: known pair table ──────────────────────────────────────────────
    for tx, rx in KNOWN_ECU_PAIRS:
        if tx in id_set and rx in id_set:
            found.append((tx, rx))
        elif tx in id_set or rx in id_set:
            found.append((tx, rx))

    # ── Step 2: J1939 29-bit address scan ─────────────────────────────────────
    # Find all 0x18DAxxxx IDs in the log, and pair by swapping source/dest bytes
    j1939_ids = [mid for mid in id_set if _j1939_is_uds_addr(mid)]
    for mid in j1939_ids:
        # Extract source (byte 0) and destination (byte 1) from J1939 PGN DA
        src = mid & 0xFF
        dst = (mid >> 8) & 0xFF
        pgn = (mid >> 8) & 0xFF00
        # Build the reverse ID
        reverse_id = (mid & 0xFF000000) | (pgn << 0) | (src << 8) | dst
        if reverse_id in id_set:
            pair = (min(mid, reverse_id), max(mid, reverse_id))
            if pair not in found and (pair[1], pair[0]) not in found:
                found.append((mid, reverse_id))

    # ── Step 3: standard +8 heuristic ────────────────────────────────────────
    for mid in sorted(id_set):
        for offset in (8, -8, 1, -1):
            other = mid + offset
            if other > 0 and other in id_set and other != mid:
                pair = (min(mid, other), max(mid, other))
                if pair not in found and (pair[1], pair[0]) not in found:
                    found.append((mid, other))

    # ── Step 4: ISO-TP / UDS pattern scan across ALL IDs ─────────────────────
    uds_traffic: Dict[int, Dict[str, int]] = defaultdict(
        lambda: {"req": 0, "resp": 0, "nrc": 0, "cf": 0})

    for msg in msgs:
        if not msg.data:
            continue
        if _looks_like_isotp_uds(msg.data):
            pci = msg.data[0]
            ft  = (pci >> 4) & 0xF
            sid = 0
            if ft == 0:
                off = 2 if (pci & 0xF) == 0 else 1
                sid = msg.data[off] if off < len(msg.data) else 0
            elif ft == 1:
                sid = msg.data[2] if len(msg.data) > 2 else 0
            elif ft == 2:
                uds_traffic[msg.msg_id]["cf"] += 1
                continue

            if sid == 0x7F:
                uds_traffic[msg.msg_id]["nrc"] += 1
            elif sid in UDS_RESPONSE_SIDS:
                uds_traffic[msg.msg_id]["resp"] += 1
            elif sid in UDS_REQUEST_SIDS:
                uds_traffic[msg.msg_id]["req"] += 1

    req_ids  = sorted(mid for mid, c in uds_traffic.items()
                      if c["req"] > 0)
    resp_ids = sorted(mid for mid, c in uds_traffic.items()
                      if c["resp"] > 0 or c["nrc"] > 0)

    # Build pairs by timing correlation
    if req_ids and resp_ids:
        # Build sorted timestamp arrays per ID for fast lookup
        resp_ts_map: Dict[int, List[float]] = {}
        for rid in resp_ids:
            resp_ts_map[rid] = sorted(m.timestamp for m in msgs if m.msg_id == rid)

        for req_id in req_ids:
            best_resp, best_score = None, 0
            req_msgs_sorted = sorted(
                (m for m in msgs if m.msg_id == req_id),
                key=lambda m: m.timestamp)
            for resp_id in resp_ids:
                if resp_id == req_id:
                    continue
                rts = resp_ts_map[resp_id]
                score = 0
                for rm in req_msgs_sorted:
                    # Count responses within 5s after this request
                    lo, hi = rm.timestamp, rm.timestamp + 5.0
                    import bisect
                    i = bisect.bisect_right(rts, lo)
                    if i < len(rts) and rts[i] <= hi:
                        score += 1
                if score > best_score:
                    best_score = score
                    best_resp  = resp_id
            if best_resp and best_score > 0:
                pair = (req_id, best_resp)
                if pair not in found and (pair[1], pair[0]) not in found:
                    found.append(pair)

    # ── Step 5: single-ID or all-UDS fallback ────────────────────────────────
    if not found and uds_traffic:
        all_uds = sorted(uds_traffic.keys(),
                         key=lambda i: -(uds_traffic[i]["req"] +
                                         uds_traffic[i]["resp"] +
                                         uds_traffic[i]["nrc"]))
        if len(all_uds) >= 2:
            found.append((all_uds[0], all_uds[1]))
        elif len(all_uds) == 1:
            found.append((all_uds[0], all_uds[0]))

    # ── Step 6: absolute fallback ─────────────────────────────────────────────
    if not found:
        id_list = sorted(id_set)
        if len(id_list) >= 2:
            found.append((id_list[0], id_list[1]))
        elif id_list:
            found.append((id_list[0], id_list[0]))
        else:
            found.append((0x7E0, 0x7E8))

    # Deduplicate while preserving order
    seen_pairs: set = set()
    result = []
    for p in found:
        key = (min(p), max(p))
        if key not in seen_pairs:
            seen_pairs.add(key)
            result.append(p)
    return result

# All UDS request service IDs (byte 0 in payload after ISO-TP)
UDS_REQUEST_SIDS = {0x10, 0x11, 0x14, 0x19, 0x22, 0x23, 0x27,
                    0x28, 0x29, 0x2A, 0x2C, 0x2E, 0x2F, 0x31,
                    0x34, 0x35, 0x36, 0x37, 0x38, 0x3D, 0x3E,
                    0x83, 0x84, 0x85, 0x86, 0x87}
# Positive response SIDs (request + 0x40)
UDS_RESPONSE_SIDS = {s | 0x40 for s in UDS_REQUEST_SIDS}
UDS_ALL_SIDS = UDS_REQUEST_SIDS | UDS_RESPONSE_SIDS | {0x7F}


def _is_uds_payload(data: bytes) -> bool:
    """Return True if this data looks like a UDS payload (after ISO-TP unwrap)."""
    if not data:
        return False
    sid = data[0]
    # NRC
    if sid == 0x7F and len(data) >= 3:
        return data[2] in UDS_NRC
    return sid in UDS_ALL_SIDS


def _looks_like_isotp_uds(data: bytes) -> bool:
    """
    Check if a raw CAN frame (8 bytes) could be carrying a UDS message via ISO-TP.
    Returns True if the ISO-TP PCI makes sense AND the payload looks like UDS.
    """
    if not data or len(data) < 2:
        return False
    pci = data[0]
    frame_type = (pci >> 4) & 0xF

    if frame_type == 0:         # Single Frame
        ln = pci & 0xF
        if ln == 0 and len(data) > 1:  # extended SF
            ln = data[1]
            payload_start = 2
        else:
            payload_start = 1
        if ln == 0 or ln > len(data) - payload_start + 1:
            return False
        sid = data[payload_start] if payload_start < len(data) else 0
        return sid in UDS_ALL_SIDS

    elif frame_type == 1:       # First Frame
        ln = ((pci & 0xF) << 8) | (data[1] if len(data) > 1 else 0)
        if ln < 7 or ln > 4095:
            return False
        sid = data[2] if len(data) > 2 else 0
        return sid in UDS_ALL_SIDS

    elif frame_type == 2:       # Consecutive Frame — less conclusive but valid
        return True

    elif frame_type == 3:       # Flow Control
        return True

    return False



def decode_uds_frames(raw: bytes, ts: float, src: int, dst: int,
                      is_resp: bool, first_can: CANMsg) -> Optional[UDSFrame]:
    if not raw:
        return None
    sid = raw[0]
    sub = raw[1] if len(raw) > 1 else None

    # Negative Response  (covers all NRCs including 0x78 responsePending)
    if sid == 0x7F and len(raw) >= 3:
        nrc_byte   = raw[2]
        is_pending = (nrc_byte == 0x78)
        frame = UDSFrame(
            timestamp=ts, src_id=src, dst_id=dst,
            service_id=raw[1], sub_func=None,
            data=raw, raw_can=[first_can],
            is_response=True, is_nrc=True,
            is_pending=is_pending, nrc_code=nrc_byte,
            line_no=first_can.line_no,
        )
        return frame

    is_pos_resp = (sid & 0x40) != 0
    actual_sid  = sid & 0xBF

    return UDSFrame(
        timestamp=ts, src_id=src, dst_id=dst,
        service_id=actual_sid, sub_func=sub,
        data=raw, raw_can=[first_can],
        is_response=is_pos_resp or is_resp,
        line_no=first_can.line_no,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# UDS FLASH ANALYSER — all detection rules
# ═══════════════════════════════════════════════════════════════════════════════
class UDSFlashAnalyzer:

    # Well-known DID identifiers
    DID_NAMES = {
        0xF186: "ActiveDiagnosticSession",
        0xF187: "VehicleManufacturerSparePartNumber",
        0xF188: "VehicleManufacturerECUSoftwareNumber",
        0xF189: "VehicleManufacturerECUSoftwareVersionNumber",
        0xF18A: "SystemSupplierIdentifier",
        0xF18B: "ECUManufacturingDate",
        0xF18C: "ECUSerialNumber",
        0xF18E: "SupportedFunctionalUnits",
        0xF190: "VehicleIdentificationNumber",
        0xF191: "VehicleManufacturerECUHardwareNumber",
        0xF192: "SystemSupplierECUHardwareNumber",
        0xF193: "SystemSupplierECUHardwareVersionNumber",
        0xF194: "SystemSupplierECUSoftwareNumber",
        0xF195: "SystemSupplierECUSoftwareVersionNumber",
        0xF197: "SystemNameOrEngineType",
        0xF198: "RepairShopCodeOrTesterSerialNumber",
        0xF199: "ProgrammingDate",
        0xF19E: "ODXFile",
        0xF1A0: "BootSoftwareIdentification",
        0xF1A2: "ApplicationSoftwareIdentification",
        0xF1A4: "ApplicationDataIdentification",
    }

    def __init__(self, frames: List[UDSFrame], can_msgs: List[CANMsg]):
        self.frames      = frames
        self.can_msgs    = can_msgs
        self.issues      : List[Issue]       = []
        self.sequences   : List[FlashSequence] = []
        self.ecu_metadata: Dict[str, str]    = {}     # DID name -> decoded value
        self.resp_times  : List[Dict]        = []     # response time per service
        self.session_log : List[Dict]        = []     # ordered session transitions
        self._analyze()

    # ─── master analysis pipeline ─────────────────────────────────────────────
    def _analyze(self):
        self._extract_ecu_metadata()
        self._build_response_times()
        self._build_session_log()
        self._build_sequences()
        for seq in self.sequences:
            self._check_session_control(seq)
            self._check_security_access(seq)
            self._check_erase(seq)
            self._check_download(seq)
            self._check_transfer(seq)
            self._check_transfer_exit(seq)
        self._check_nrc_codes()
        self._check_timeouts()
        self._check_tp2_expiry()
        self._check_block_sequence()
        self._check_tester_present()
        self._check_comm_control()
        self._check_dtc_setting()
        self._check_response_pending_flood()
        self._check_wrong_session()
        self._check_data_integrity()
        self._check_sequence_order()
        self._check_subfunc_not_supported()
        self._check_custom_sessions()
        self.issues.sort(key=lambda i: (i.sev_order, i.timestamp or 0))

    # ─── ECU metadata extraction ──────────────────────────────────────────────
    def _extract_ecu_metadata(self):
        """Extract VIN, software version etc. from 0x62 (ReadDID) responses."""
        for f in self.frames:
            sid = f.service_id & 0xBF
            if sid == 0x22 and f.is_response and len(f.data) >= 4:
                # Positive ReadDID response: 62 DID_H DID_L DATA...
                did = (f.data[1] << 8) | f.data[2]
                raw_val = f.data[3:]
                # Try ASCII decode first
                try:
                    val = raw_val.decode("ascii").strip("\x00").strip()
                    if not val or not val.isprintable():
                        raise ValueError
                except (UnicodeDecodeError, ValueError):
                    val = raw_val.hex().upper()
                name = self.DID_NAMES.get(did, f"DID_0x{did:04X}")
                self.ecu_metadata[name] = val

    # ─── response time analysis ───────────────────────────────────────────────
    @staticmethod
    def _ts_to_log_time(ts: float) -> str:
        """Convert float seconds back to HH:MM:SS:mmmm display format."""
        h   = int(ts) // 3600
        m   = (int(ts) % 3600) // 60
        s   = int(ts) % 60
        ms  = round((ts - int(ts)) * 10000)   # 0.1ms ticks (4 digits)
        return f"{h:02d}:{m:02d}:{s:02d}:{ms:04d}"

    def _build_response_times(self):
        """
        Pair each request with its closest response and record timing.

        BUG FIX: each response is now consumed only once. The old code re-used
        the same response frame for multiple requests of the same SID, causing
        artificially large latencies (e.g. 5 consecutive RDI requests all
        paired to a single response that only answered the last one).

        Also stores: CAN ID of req/resp, raw data bytes (first 8), original
        log-format timestamp string for report display.
        """
        reqs = [f for f in self.frames if not f.is_response and not f.is_nrc]
        # Build a mutable list of available responses, sorted by timestamp
        available_resps = [f for f in self.frames
                           if f.is_response and not (f.is_nrc and f.nrc_code == 0x78)]
        available_resps.sort(key=lambda x: x.timestamp)
        consumed = set()   # id(frame) — each response consumed at most once

        for req in reqs:
            sid = req.service_id & 0xBF
            # Find the earliest unconsumed response for this SID after this request
            resp = None
            for r in available_resps:
                if id(r) in consumed:
                    continue
                if r.timestamp <= req.timestamp:
                    continue
                if r.timestamp > req.timestamp + 30.0:
                    break
                if (r.service_id & 0xBF) != sid:
                    continue
                resp = r
                break
            if resp is None:
                continue
            consumed.add(id(resp))
            delta_ms = (resp.timestamp - req.timestamp) * 1000

            # First raw CAN frame for req and resp (for data display)
            req_can  = req.raw_can[0]  if req.raw_can  else None
            resp_can = resp.raw_can[0] if resp.raw_can else None

            self.resp_times.append({
                "service":    UDS_SERVICES.get(sid, f"0x{sid:02X}"),
                "sid":        sid,
                "sub":        f"0x{req.sub_func:02X}" if req.sub_func is not None else "—",
                "req_ts":     req.timestamp,
                "resp_ts":    resp.timestamp,
                "req_log_ts": self._ts_to_log_time(req.timestamp),
                "rsp_log_ts": self._ts_to_log_time(resp.timestamp),
                "delta_ms":   round(delta_ms, 2),
                "is_nrc":     resp.is_nrc,
                "nrc_code":   resp.nrc_code if resp.is_nrc else 0,
                "req_can_id": f"0x{req_can.msg_id:X}" if req_can else "—",
                "rsp_can_id": f"0x{resp_can.msg_id:X}" if resp_can else "—",
                "req_data":   req.data[:8].hex().upper() if req.data else "—",
                "rsp_data":   resp.data[:8].hex().upper() if resp.data else "—",
            })

    # ─── session flow log ─────────────────────────────────────────────────────
    def _build_session_log(self):
        """Build ordered list of session transitions."""
        SESSION_NAMES = {
            0x01: "defaultSession",
            0x02: "programmingSession",
            0x03: "extendedDiagnosticSession",
            0x04: "safetySystemDiagnosticSession",
            0x60: "OBDIIDiagnosticSession",
        }
        for f in self.frames:
            sid = f.service_id & 0xBF
            if sid == 0x10:
                sub = f.data[1] if len(f.data) > 1 else 0
                result = "OK" if (f.is_response and not f.is_nrc) else \
                         ("PENDING" if (f.is_nrc and f.nrc_code == 0x78) else
                          (f"NRC 0x{f.nrc_code:02X}" if f.is_nrc else "REQ"))
                self.session_log.append({
                    "ts":      f.timestamp,
                    "sub":     sub,
                    "name":    SESSION_NAMES.get(sub, f"customSession_0x{sub:02X}"),
                    "result":  result,
                    "is_resp": f.is_response,
                    "is_nrc":  f.is_nrc,
                })

    # ─── additional NRC checks ────────────────────────────────────────────────
    def _check_subfunc_not_supported(self):
        """Detect NRC 0x12 — subFunctionNotSupported (wrong security level)."""
        for f in self.frames:
            if f.is_nrc and f.nrc_code == 0x12:
                self._add(Issue(
                    severity="ERROR", code="UDS-023",
                    title="NRC 0x12 — subFunctionNotSupported (Wrong Security Level)",
                    description=(
                        f"Service 0x{f.service_id:02X} returned NRC 0x12 at "
                        f"t={f.timestamp:.3f}s. "
                        "The sub-function (e.g. SecurityAccess level) is not supported "
                        "in the current session or by this ECU variant."
                    ),
                    timestamp=f.timestamp,
                    service=f"0x{f.service_id:02X} {UDS_SERVICES.get(f.service_id,'?')}",
                    raw_data=f.data.hex().upper(),
                    root_cause=(
                        "1. Wrong SecurityAccess level (e.g. 0x61/0x62 when ECU expects 0x01/0x02).\n"
                        "2. Service sub-function not configured for this ECU variant.\n"
                        "3. Tester using programming sub-function in wrong session.\n"
                        "4. ECU firmware version mismatch with flash specification."
                    ),
                    corrective_action=(
                        "1. Check ECU specification for supported SecurityAccess levels.\n"
                        "2. Confirm required session before calling SecurityAccess.\n"
                        "3. Try sub-function 0x01 (seedRequest) and 0x02 (sendKey) in programming session.\n"
                        "4. Verify flash spec matches the ECU software baseline."
                    ),
                    preventive_action=(
                        "• Validate sub-function list against ECU specification before flash sequence.\n"
                        "• Maintain ECU-variant-specific flash parameter files.\n"
                        "• Add sub-function support check (0x27 00) if ECU supports it."
                    ),
                    line_no=f.line_no,
                ))

    def _check_custom_sessions(self):
        """Detect use of non-standard session IDs (e.g. 0x61, 0x60...)."""
        STANDARD = {0x01, 0x02, 0x03, 0x04, 0x60}
        seen = set()
        for f in self.frames:
            sid = f.service_id & 0xBF
            if sid == 0x10 and not f.is_response:
                sub = f.data[1] if len(f.data) > 1 else 0
                if sub not in STANDARD and sub not in seen:
                    seen.add(sub)
                    self._add(Issue(
                        severity="INFO", code="UDS-024",
                        title=f"Non-Standard Session 0x{sub:02X} Requested",
                        description=(
                            f"DiagnosticSessionControl requested session 0x{sub:02X} "
                            f"at t={f.timestamp:.3f}s. "
                            "This is a proprietary/non-standard session ID not defined "
                            "in ISO 14229-1."
                        ),
                        timestamp=f.timestamp,
                        service="0x10 DiagnosticSessionControl",
                        raw_data=f.data.hex().upper(),
                        root_cause=(
                            f"ECU uses a manufacturer-specific diagnostic session 0x{sub:02X}. "
                            "This is common in heavy-vehicle (J1939) ECUs like Albonair, "
                            "Bosch, and Delphi where OEM-defined sessions extend standard UDS."
                        ),
                        corrective_action=(
                            f"1. Confirm session 0x{sub:02X} is required by the ECU flash spec.\n"
                            "2. Verify the session is entered before security access.\n"
                            "3. Check if SecurityAccess level matches this custom session."
                        ),
                        preventive_action=(
                            "• Document all proprietary sessions in the ECU flash parameter file.\n"
                            "• Create session-service mapping table for each ECU variant."
                        ),
                        line_no=f.line_no,
                    ))

    # ─── build flash sequences ────────────────────────────────────────────────
    def _build_sequences(self):
        """
        Build FlashSequence objects by scanning UDS frames.

        Programming session trigger: DSC request with sub == 0x02 OR any
        proprietary sub-function that gets a positive DSC response (0x50).
        The ECU's positive response (0x50 + sub) is the authoritative
        confirmation that a programming/flash session is active.
        """
        current: Optional[FlashSequence] = None

        for f in self.frames:
            sid = f.service_id & 0xBF
            sub = f.sub_func if f.sub_func is not None else (
                f.data[1] if len(f.data) > 1 else 0)

            # ── DiagnosticSessionControl ──────────────────────────────────────
            if sid == 0x10:
                if not f.is_response and not f.is_nrc:
                    # Any programming-related session request starts tracking
                    # sub=0x02 = standard, sub>=0x40 = proprietary (e.g. 0x61)
                    is_prog_sub = (sub == 0x02 or sub >= 0x40)
                    if is_prog_sub:
                        if current:
                            if current.session_end is None:
                                current.session_end = f.timestamp
                            self.sequences.append(current)
                        current = FlashSequence(
                            session_start=f.timestamp,
                            ecu_address=f.src_id,
                        )
                    elif sub == 0x01 and current:
                        # Returning to default session ends the sequence
                        current.session_end = f.timestamp

                elif f.is_response and not f.is_nrc and current is not None:
                    # Positive DSC response (0x50 xx) confirms session entered
                    # sub in response mirrors the request sub-function
                    if sub == 0x02 or sub >= 0x40:
                        current.programming_session = True

            if current is None:
                continue

            # ── SecurityAccess ────────────────────────────────────────────────
            if sid == 0x27:
                if f.is_response and not f.is_nrc:
                    # Positive response to SendKey: sub is even (0x02, 0x04, 0x62…)
                    if sub % 2 == 0 and sub != 0:
                        current.security_access_ok = True

            # ── RoutineControl ────────────────────────────────────────────────
            elif sid == 0x31:
                if f.is_response and not f.is_nrc:
                    # Positive response: 71 01 RID_H RID_L ...
                    rid = (f.data[2] << 8 | f.data[3]) if len(f.data) > 3 else 0
                    # Erase routines: 0xFF00, 0xFF01, 0xFF02, 0xF003 (flash driver init)
                    ERASE_RIDS = {0xFF00, 0xFF01, 0xFF02, 0xF003, 0xFF04, 0xFF10}
                    if rid in ERASE_RIDS:
                        current.erase_ok = True
                    # BUG FIX: was a dead-code duplicate elif sid==0x31 (unreachable).
                    # CheckMemory / CheckApplicationSoftware RIDs now checked here.
                    CHECK_RIDS = {0x0202, 0x0203, 0x0204, 0x0205, 0x0206}
                    if rid in CHECK_RIDS:
                        current.check_ok = True

            # ── RequestDownload ───────────────────────────────────────────────
            elif sid == 0x34:
                # Either the request or positive response counts
                if not f.is_nrc:
                    current.download_requested = True

            # ── TransferData ──────────────────────────────────────────────────
            elif sid == 0x36:
                if not f.is_nrc and not f.is_response:
                    current.transfer_frames += 1

            # ── RequestTransferExit ───────────────────────────────────────────
            elif sid == 0x37:
                if f.is_response and not f.is_nrc:
                    current.transfer_exit_ok = True

            current.frames.append(f)

        if current:
            if current.session_end is None:
                current.session_end = (
                    self.frames[-1].timestamp if self.frames else None)
            self.sequences.append(current)

    # ─── individual checks ────────────────────────────────────────────────────
    def _check_session_control(self, seq: FlashSequence):
        if not seq.programming_session:
            self._add(Issue(
                severity="CRITICAL", code="UDS-001",
                title="Programming Session Not Established",
                description=(
                    "No positive response to DiagnosticSessionControl(0x10) "
                    "subFunction=0x02 (programmingSession) was detected. "
                    "The ECU never entered programming mode."
                ),
                timestamp=seq.session_start,
                service="0x10 DiagnosticSessionControl",
                raw_data="REQ: 10 02  |  RSP: not found",
                root_cause=(
                    "Possible causes: (1) ECU not powered / not on bus, "
                    "(2) Incorrect tester address, "
                    "(3) ECU in bootlock / security lockout, "
                    "(4) Pre-conditions not met (e.g. vehicle speed > 0, "
                    "ignition not in correct state), "
                    "(5) Tester send timing too early after power-up."
                ),
                corrective_action=(
                    "1. Verify ECU power supply and CAN bus termination (120 Ohm each end).\n"
                    "2. Confirm tester CAN ID matches ECU physical address (e.g. 0x7E0).\n"
                    "3. Check vehicle pre-conditions: ignition ON, engine OFF, speed = 0.\n"
                    "4. Wait at least 500 ms after ECU power-up before sending 0x10 02.\n"
                    "5. Try sending TesterPresent (0x3E 00) first to wake up ECU."
                ),
                preventive_action=(
                    "• Add pre-condition check script that validates vehicle state before flashing.\n"
                    "• Implement ECU detection loop (read 0x22 F1 90) before starting flash.\n"
                    "• Document minimum power-up delay in flash specification."
                ),
            ))

    def _check_security_access(self, seq: FlashSequence):
        if seq.programming_session and not seq.security_access_ok:
            sa_frames = [f for f in seq.frames if (f.service_id & 0xBF) == 0x27]
            nrc_35 = any(f.is_nrc and f.nrc_code == 0x35 for f in sa_frames)
            nrc_36 = any(f.is_nrc and f.nrc_code == 0x36 for f in sa_frames)
            ts     = sa_frames[0].timestamp if sa_frames else seq.session_start
            if nrc_36:
                desc = "Security Access failed with NRC 0x36 (exceededNumberOfAttempts). ECU is locked."
                rc   = ("Too many failed seed-key attempts caused the ECU to lock. "
                        "Common root causes: (1) wrong key algorithm or seed XOR mask, "
                        "(2) byte-swapped key value, (3) incorrect security level (01/03/05...).")
                ca   = ("1. Power-cycle the ECU and wait the full anti-attack delay (typically 10 min).\n"
                        "2. Verify the seed-key DLL / algorithm matches the target ECU variant.\n"
                        "3. Do not retry security access more than 2 times before power-cycling.")
                pa   = ("• Limit security access retries in flash tool to 1.\n"
                        "• Log seed and computed key for every attempt for post-mortem analysis.\n"
                        "• Validate key algorithm against ECU specification before production use.")
            elif nrc_35:
                desc = "Security Access failed with NRC 0x35 (invalidKey). Wrong seed-key algorithm."
                rc   = ("Computed key does not match ECU expected key. "
                        "Root causes: (1) wrong algorithm variant, (2) incorrect seed length, "
                        "(3) platform-specific XOR/bit-manipulation differences.")
                ca   = ("1. Compare seed-key algorithm against ECU supplier documentation.\n"
                        "2. Test the algorithm with known-good seed/key pairs from the supplier.\n"
                        "3. Check endianness — some ECUs expect key in big-endian, others little-endian.")
                pa   = ("• Maintain a signed, version-controlled seed-key DLL per ECU variant.\n"
                        "• Include algorithm self-test in flash tool startup.")
            else:
                desc = "Security Access (0x27) sequence did not complete successfully."
                rc   = ("Security Access positive response not received. "
                        "The ECU may be rejecting the request or not responding.")
                ca   = ("1. Confirm security level in request matches ECU (e.g. 0x01 for programming).\n"
                        "2. Ensure programming session is active before sending 0x27.\n"
                        "3. Check timing: send key within P2* timeout after receiving seed.")
                pa   = ("• Validate security access step in offline simulation before vehicle test.\n"
                        "• Use 0x27 sub-function 0x00 to query supported levels first.")
            self._add(Issue(
                severity="CRITICAL", code="UDS-002",
                title="Security Access Failed",
                description=desc,
                timestamp=ts,
                service="0x27 SecurityAccess",
                raw_data=" | ".join(f"{f.data.hex().upper()}" for f in sa_frames[:4]),
                root_cause=rc, corrective_action=ca, preventive_action=pa,
            ))

    def _check_erase(self, seq: FlashSequence):
        # BUG FIX: Only flag missing erase if a download was actually attempted.
        # Some ECUs auto-erase during RequestDownload or inside the flash driver —
        # reporting "erase not done" when download succeeded creates false positives.
        if seq.programming_session and seq.security_access_ok and not seq.erase_ok and seq.download_requested:
            ts = next((f.timestamp for f in seq.frames if (f.service_id&0xBF)==0x31), seq.session_start)
            self._add(Issue(
                severity="CRITICAL", code="UDS-003",
                title="Memory Erase Routine Failed",
                description=(
                    "RoutineControl(0x31) EraseMemory (0xFF00) did not return a positive response. "
                    "Flash memory was not erased; subsequent download will fail."
                ),
                timestamp=ts,
                service="0x31 RoutineControl (EraseMemory 0xFF00)",
                raw_data="31 01 FF 00 ...",
                root_cause=(
                    "1. Memory already erased (some ECUs reject duplicate erase).\n"
                    "2. Incorrect memory address / length parameter in erase request.\n"
                    "3. ECU flash driver not initialised prior to erase.\n"
                    "4. Supply voltage below minimum flash threshold (~11.5 V).\n"
                    "5. Flash block marked as write-protected by bootloader."
                ),
                corrective_action=(
                    "1. Verify erase start address and length match ECU memory map.\n"
                    "2. Download and execute flash driver (0x34/0x36) before erasing if required.\n"
                    "3. Measure supply voltage: must be 11.5–14.5 V during erase.\n"
                    "4. Check 0x31 01 F0 03 (FlashDriverInit) is sent before EraseMemory."
                ),
                preventive_action=(
                    "• Include flash driver init step in flash sequence template.\n"
                    "• Monitor supply voltage channel in flash tool and abort if < 11.5 V.\n"
                    "• Validate memory map addresses against ECU variant before flashing."
                ),
            ))

    def _check_download(self, seq: FlashSequence):
        if seq.programming_session and seq.security_access_ok and not seq.download_requested:
            self._add(Issue(
                severity="ERROR", code="UDS-004",
                title="RequestDownload (0x34) Not Sent or Rejected",
                description=(
                    "No successful RequestDownload (0x34) was detected after security access. "
                    "The data transfer phase was never initiated."
                ),
                timestamp=seq.session_start,
                service="0x34 RequestDownload",
                raw_data="34 00 44 ...",
                root_cause=(
                    "1. RequestDownload parameters incorrect (dataFormatIdentifier, "
                    "memoryAddressAndLengthIdentifier).\n"
                    "2. ECU returned NRC 0x70 (uploadDownloadNotAccepted).\n"
                    "3. Erase was not confirmed before download was requested.\n"
                    "4. Address/size encoding mismatch between tester and ECU spec."
                ),
                corrective_action=(
                    "1. Verify dataFormatIdentifier byte (usually 0x00 = no compression).\n"
                    "2. Confirm memoryAddressAndLengthIdentifier nibbles match address/size byte counts.\n"
                    "3. Ensure erase routine positive response was received before 0x34.\n"
                    "4. Check maximum block length from 0x34 positive response and segment accordingly."
                ),
                preventive_action=(
                    "• Auto-calculate addressing parameters from hex/s19 file parser.\n"
                    "• Log 0x34 positive response and extract maxBlockLength for transfer sizing."
                ),
            ))

    def _check_transfer(self, seq: FlashSequence):
        if seq.download_requested and seq.transfer_frames == 0:
            self._add(Issue(
                severity="CRITICAL", code="UDS-005",
                title="No TransferData (0x36) Frames Sent",
                description=(
                    "RequestDownload was accepted but no TransferData frames were transmitted. "
                    "Flash image was never written to ECU."
                ),
                timestamp=seq.session_start,
                service="0x36 TransferData",
                raw_data="36 01 ...",
                root_cause=(
                    "1. Flash tool crashed or timed out after 0x34 positive response.\n"
                    "2. Flash image file missing, corrupt, or wrong format (e.g. SRecord vs Intel HEX).\n"
                    "3. Incorrect maxBlockLength parsed from 0x34 response."
                ),
                corrective_action=(
                    "1. Verify flash image file integrity (CRC/checksum).\n"
                    "2. Re-parse 0x34 positive response: maxBlockLength field must not be 0.\n"
                    "3. Check flash tool logs for exceptions between 0x34 response and 0x36 request."
                ),
                preventive_action=(
                    "• Validate flash image CRC before starting any UDS session.\n"
                    "• Include file format validation (SRecord / Intel HEX) at tool startup."
                ),
            ))
        elif seq.download_requested and seq.transfer_frames > 0 and not seq.transfer_exit_ok:
            self._add(Issue(
                severity="ERROR", code="UDS-006",
                title="TransferData Incomplete — Transfer Never Exited",
                description=(
                    f"TransferData was in progress ({seq.transfer_frames} block(s) sent) "
                    "but RequestTransferExit (0x37) was not confirmed. "
                    "Flash image may be partially written."
                ),
                timestamp=seq.session_start,
                service="0x36/0x37 TransferData/RequestTransferExit",
                raw_data=f"36 xx ... ({seq.transfer_frames} frames) | 37 not confirmed",
                root_cause=(
                    "1. ECU returned NRC during TransferData (0x72 generalProgrammingFailure, "
                    "0x73 wrongBlockSequenceCounter).\n"
                    "2. Tester disconnected or timed out mid-transfer.\n"
                    "3. CAN bus error during large block causing ISO-TP reassembly failure.\n"
                    "4. Supply voltage drop during erase/write causing ECU reset."
                ),
                corrective_action=(
                    "1. Check each 0x36 response for NRC codes — 0x72 or 0x73 indicate flash write failure.\n"
                    "2. Re-erase and restart download from the beginning.\n"
                    "3. Monitor CAN bus load during transfer — keep < 70% to avoid flow control issues.\n"
                    "4. Monitor supply voltage; a drop > 0.5 V during write is critical."
                ),
                preventive_action=(
                    "• Implement retry logic for individual transfer blocks (max 3 retries).\n"
                    "• Add CAN bus load monitor that pauses transfer if load > 70%.\n"
                    "• Use a power-stable bench supply (not just vehicle battery) during development."
                ),
            ))

    def _check_transfer_exit(self, seq: FlashSequence):
        if seq.transfer_exit_ok and not seq.check_ok:
            check_frames = [f for f in seq.frames
                            if (f.service_id&0xBF)==0x31
                            and len(f.data) > 3
                            and ((f.data[2]<<8)|f.data[3]) in (0x0202,0x0203,0xFF01)]
            if not check_frames:
                self._add(Issue(
                    severity="WARNING", code="UDS-007",
                    title="Post-Flash Integrity Check Not Performed",
                    description=(
                        "RequestTransferExit completed but no CheckMemory / "
                        "CheckApplicationSoftware routine (0x31 01 02 02 / 02 03) was detected. "
                        "Flash integrity was not verified."
                    ),
                    timestamp=seq.session_end,
                    service="0x31 RoutineControl (CheckMemory 0x0202)",
                    raw_data="31 01 02 02 ...",
                    root_cause=(
                        "Flash sequence template missing the mandatory post-programming check step. "
                        "Without this, a CRC/checksum mismatch in flash will not be detected."
                    ),
                    corrective_action=(
                        "1. After 0x37 positive response, send 0x31 01 02 02 (CheckMemory).\n"
                        "2. Wait for positive response 0x71 01 02 02 00 (pass) before resetting ECU.\n"
                        "3. If 0x31 returns NRC 0x72, the flash is corrupt — re-flash."
                    ),
                    preventive_action=(
                        "• Make CheckMemory a mandatory step in the flash sequence template.\n"
                        "• Fail the flash operation if CheckMemory is not explicitly passed."
                    ),
                ))

    def _check_nrc_codes(self):
        """Detailed analysis of every NRC received."""
        nrc_checks = {
            0x22: ("UDS-010", "ERROR",
                   "NRC 0x22 — conditionsNotCorrect",
                   "ECU rejected request because conditions are not met (e.g. wrong session, speed != 0, battery voltage).",
                   "1. Verify all pre-conditions (session, voltage, speed, DTC status).\n2. Send 0x28 02 01 (disable Rx/Tx) before flash.\n3. Check ECU specification for pre-condition list.",
                   "• Add pre-condition validation step in flash sequence.\n• Document all ECU-specific conditions."),
            0x24: ("UDS-011", "ERROR",
                   "NRC 0x24 — requestSequenceError",
                   "Service was called out of the expected UDS sequence order.",
                   "1. Validate the flash sequence order against ECU specification.\n2. Ensure session → security → disable DTC → disable comm → erase → download → exit → check → reset.",
                   "• Encode mandatory sequence into flash tool state machine.\n• Reject sequence deviations programmatically."),
            0x31: ("UDS-012", "WARNING",
                   "NRC 0x31 — requestOutOfRange",
                   "The ECU rejected the request because a parameter (DID, address, sub-function, "
                   "or routine identifier) is outside its accepted range.",
                   "1. For 0x22 ReadDataByIdentifier: verify the DID is supported by this ECU variant "
                   "(check ECU supplier DID list).\n"
                   "2. For 0x34 RequestDownload / 0x23 ReadMemoryByAddress: verify address and length "
                   "are within the ECU memory map.\n"
                   "3. For 0x31 RoutineControl: verify the Routine ID is listed in ECU specification.\n"
                   "4. Check that the sub-function byte is valid for the current session.",
                   "• Maintain a per-ECU-variant DID/RID support list and validate requests against it.\n"
                   "• Add range validation in the flash tool before each service request.\n"
                   "• Use 0x22 F1 8E (SupportedFunctionalUnits) to query supported DIDs before reading."),
            0x33: ("UDS-013", "CRITICAL",
                   "NRC 0x33 — securityAccessDenied",
                   "ECU denied service access. Security level not unlocked.",
                   "1. Complete SecurityAccess (0x27) successfully before this service.\n2. Check required security level for this service in ECU spec.",
                   "• Never skip security access step.\n• Log security access state before each privileged service."),
            0x35: ("UDS-014", "CRITICAL",
                   "NRC 0x35 — invalidKey",
                   "Security key computation is wrong. Seed-key algorithm mismatch.",
                   "1. Re-verify seed-key algorithm with ECU supplier.\n2. Check endianness of seed bytes.\n3. Validate with known test vectors.",
                   "• Version-control seed-key algorithms with ECU software baseline.\n• Automate algorithm verification before each release."),
            0x36: ("UDS-015", "CRITICAL",
                   "NRC 0x36 — exceededNumberOfAttempts",
                   "Too many failed security access attempts. ECU is in anti-tamper lockout.",
                   "1. Power-cycle ECU and wait anti-attack delay (check spec, typically 10 min).\n2. Do NOT retry immediately.\n3. Fix algorithm before next attempt.",
                   "• Limit flash tool to 1 security attempt before halting.\n• Alert operator before any retry."),
            0x70: ("UDS-016", "ERROR",
                   "NRC 0x70 — uploadDownloadNotAccepted",
                   "ECU refused the RequestDownload/Upload. Memory not ready or pre-conditions unmet.",
                   "1. Confirm EraseMemory routine completed successfully.\n2. Check supply voltage.\n3. Verify dataFormatIdentifier = 0x00 (no encryption).",
                   "• Add explicit erase confirmation check before 0x34.\n• Monitor supply voltage throughout sequence."),
            0x71: ("UDS-017", "WARNING",
                   "NRC 0x71 — transferDataSuspended",
                   "ECU suspended the transfer. Likely an internal flash write buffer issue.",
                   "1. Reduce transfer block size.\n2. Increase inter-block delay.\n3. Check if ECU requires flow control (FC) frame handling.",
                   "• Implement adaptive block size based on ECU capability response.\n• Add configurable inter-block delay parameter."),
            0x72: ("UDS-018", "CRITICAL",
                   "NRC 0x72 — generalProgrammingFailure",
                   "Flash write or erase operation failed inside the ECU. Memory may be damaged.",
                   "1. Power-cycle ECU and attempt full re-flash from erase.\n2. Check supply voltage was stable during write.\n3. Verify flash driver is compatible with this ECU hardware revision.",
                   "• Always verify supply voltage before and during flash.\n• Log ECU hardware revision and validate flash driver compatibility matrix."),
            0x73: ("UDS-019", "CRITICAL",
                   "NRC 0x73 — wrongBlockSequenceCounter",
                   "Block sequence counter in TransferData (0x36) is incorrect. Sequence is broken.",
                   "1. Ensure blockSequenceCounter starts at 0x01 and wraps at 0xFF→0x00.\n2. Restart transfer from 0x34.\n3. Check for packet loss on CAN bus.",
                   "• Implement sequence counter in flash tool with wrap-around logic.\n• Add CAN error frame monitoring to detect bus issues during transfer."),
            0x78: ("UDS-020", "INFO",
                   "NRC 0x78 — responsePending (RCRRP)",
                   "ECU acknowledged the request but needs more time. Tool must wait and not re-send.",
                   "1. Increase tester P2* timeout to accommodate ECU processing time.\n2. Do not re-send the request; wait for the final response.\n3. Count pending responses — if > 10, check for ECU hang.",
                   "• Set P2* ≥ 5 seconds for erase and check operations.\n• Implement pending response counter with alarm threshold."),
            0x7E: ("UDS-021", "ERROR",
                   "NRC 0x7E — subFunctionNotSupportedInActiveSession",
                   "The sub-function is valid but not allowed in the current session.",
                   "1. Switch to the correct session (e.g. programmingSession for download).\n2. Check which session is currently active using 0x10 responses.",
                   "• Enforce session state machine in flash tool.\n• Never send programming-only services in defaultSession."),
            0x7F: ("UDS-022", "ERROR",
                   "NRC 0x7F — serviceNotSupportedInActiveSession",
                   "The requested service is not supported in the current active session.",
                   "1. Verify you are in the correct session.\n2. Check ECU specification for session-service matrix.",
                   "• Implement session-service validation matrix in flash tool.\n• Block services not applicable to current session state."),
        }
        # BUG FIX: exclude responsePending (0x78) from NRC issue reporting —
        # 0x78 is normal ECU behaviour, not a failure. It is already handled
        # by _check_response_pending_flood for the case where there are too many.
        EXCLUDE_FROM_ISSUE = {0x78}
        nrc_frames = [f for f in self.frames if f.is_nrc and f.nrc_code not in EXCLUDE_FROM_ISSUE]
        seen = set()
        for f in nrc_frames:
            if f.nrc_code in nrc_checks and f.nrc_code not in seen:
                seen.add(f.nrc_code)
                code, sev, title, desc, ca, pa = nrc_checks[f.nrc_code]
                self._add(Issue(
                    severity=sev, code=code, title=title, description=desc,
                    timestamp=f.timestamp,
                    service=f"0x{f.service_id:02X} {UDS_SERVICES.get(f.service_id,'?')}",
                    raw_data=f.data.hex().upper(),
                    root_cause=f"Received NRC 0x{f.nrc_code:02X}: {UDS_NRC.get(f.nrc_code,'?')}",
                    corrective_action=ca, preventive_action=pa,
                    line_no=f.line_no,
                ))

    def _check_timeouts(self):
        """Detect request frames with no matching response within P2* window.

        FIX: Extended search window to 30s to cover ECUs that send NRC 0x78
        (responsePending) for long operations (erase, check memory).
        A request is only flagged as timed-out if:
          - No matching response (positive, NRC, OR pending 0x78) found within 30s
          - AND it is a flash-critical service (not default-session DSC 0x01 which
            is routinely retried by flash tools and not a real error)
        Also: DSC sub=0x01 (return to default session) is excluded — tools send
        these repeatedly as probes and missing one is not a true timeout.
        """
        P2S_MAX = 30.0     # 30 s — covers long erase + multiple 0x78 pendings
        reqs = [f for f in self.frames if not f.is_response and not f.is_nrc]
        for req in reqs:
            sid = req.service_id & 0xBF
            sub = req.sub_func if req.sub_func is not None else (
                req.data[1] if len(req.data) > 1 else 0)

            # Skip DSC sub=0x01 (defaultSession probe — not a flash service)
            if sid == 0x10 and sub == 0x01:
                continue

            # Look for a real response OR a pending (0x78) after this request
            resp = next((f for f in self.frames
                         if (f.service_id & 0xBF) == sid
                         and f.timestamp > req.timestamp
                         and f.timestamp < req.timestamp + P2S_MAX
                         and (f.is_response or (f.is_nrc and f.nrc_code == 0x78))), None)
            if resp is None and sid in (0x34, 0x36, 0x37, 0x31, 0x27, 0x10):
                self._add(Issue(
                    severity="ERROR", code="UDS-030",
                    title=f"No Response to {UDS_SERVICES.get(sid,'SID 0x'+hex(sid))} (Timeout)",
                    description=(
                        f"Request for service 0x{sid:02X} "
                        f"({UDS_SERVICES.get(sid,'?')}) at t={req.timestamp:.3f}s "
                        "received no ECU response within the P2* window."
                    ),
                    timestamp=req.timestamp,
                    service=f"0x{sid:02X} {UDS_SERVICES.get(sid,'?')}",
                    raw_data=req.data.hex().upper(),
                    root_cause=(
                        "1. CAN bus issue (termination fault, wiring, EMI).\n"
                        "2. ECU not powered or in reset.\n"
                        "3. Wrong tester or ECU CAN ID.\n"
                        "4. ECU internally busy (previous operation still running)."
                    ),
                    corrective_action=(
                        "1. Verify CAN bus termination (should be ~60 Ohm diff).\n"
                        "2. Confirm ECU is powered and CAN frames are visible on bus.\n"
                        "3. Send TesterPresent (0x3E 00) first and check for response.\n"
                        "4. Extend P2* timeout in tester configuration."
                    ),
                    preventive_action=(
                        "• Always monitor for response before proceeding to next step.\n"
                        "• Implement timeout handling with automatic retry (max 3) and error logging."
                    ),
                    line_no=req.line_no,
                ))

    def _check_tp2_expiry(self):
        """Detect excessive gap between TransferData blocks within a single download segment.

        FIX: Filters out segment-boundary transitions. A gap between the last 0x76
        of one download and the first 0x36 of the next download is NORMAL — there is
        a 0x37 RequestTransferExit + optional 0x31 check + new 0x34 RequestDownload
        in between, which takes legitimate time.
        Only flag gaps that are within a continuous 0x36 sequence (no 0x37/0x34
        between the 0x76 and the next 0x36).
        """
        CF_GAP_MAX = 0.500   # 500ms: conservative threshold for mid-segment host delay
        td_reqs  = [f for f in self.frames if (f.service_id & 0xBF) == 0x36 and not f.is_response and not f.is_nrc]
        td_resps = [f for f in self.frames if (f.service_id & 0xBF) == 0x36 and f.is_response and not f.is_nrc]
        # Build a set of timestamps where a segment boundary happens
        # (0x37 RequestTransferExit or 0x34 RequestDownload between resp and next req)
        boundary_services = {0x37, 0x34}
        boundary_ts = set(f.timestamp for f in self.frames
                          if (f.service_id & 0xBF) in boundary_services)

        for i in range(1, len(td_reqs)):
            req = td_reqs[i]
            prev_resp = next((r for r in reversed(td_resps) if r.timestamp < req.timestamp), None)
            if prev_resp is None:
                continue
            gap = req.timestamp - prev_resp.timestamp
            # Skip if a segment boundary (0x37 or 0x34) exists between prev_resp and req
            # — this is a new download segment, not a mid-transfer delay
            if any(prev_resp.timestamp < bts < req.timestamp for bts in boundary_ts):
                continue
            td_frames = td_reqs  # keep for line_no reference
            if gap > CF_GAP_MAX:
                self._add(Issue(
                    severity="ERROR", code="UDS-031",
                    title="P2* Timer Likely Expired During TransferData",
                    description=(
                        f"Gap of {gap*1000:.1f} ms detected between 0x76 response and next "
                        f"0x36 request at t={prev_resp.timestamp:.3f}s. "
                        f"Tester-side delay limit: {CF_GAP_MAX*1000:.0f} ms. "
                        "ECU may have dropped the session before next block arrived."
                    ),
                    timestamp=prev_resp.timestamp,
                    service="0x36 TransferData (ISO-TP timing)",
                    raw_data=f"Block gap: {gap*1000:.1f} ms",
                    root_cause=(
                        "1. Host CPU busy (disk I/O, memory allocation) delaying frame construction.\n"
                        "2. Flash image read from slow storage.\n"
                        "3. Excessive logging or UI updates between block sends.\n"
                        "4. CAN driver queue full."
                    ),
                    corrective_action=(
                        "1. Pre-load entire flash image into RAM before starting transfer.\n"
                        "2. Disable non-critical logging during transfer.\n"
                        "3. Use a real-time or high-priority thread for frame sending.\n"
                        "4. Reduce block size to allow faster construction."
                    ),
                    preventive_action=(
                        "• Buffer all transfer blocks in memory before sending first block.\n"
                        "• Use high-resolution timer to enforce maximum inter-block gap.\n"
                        "• Profile flash tool CPU usage on target hardware."
                    ),
                    line_no=td_frames[i].line_no,
                ))

    def _check_block_sequence(self):
        """
        Detect wrong blockSequenceCounter in 0x36 TransferData request frames.

        ISO 14229-1 rule:
          - First block after each 0x34 RequestDownload: counter resets to 0x01
          - Each subsequent block: counter += 1
          - Rollover: 0xFF → 0x00 → 0x01 → ...
          - Retry: server SHALL accept same counter value (do not advance expected)

        KEY FIX: expected_seq resets to 0x01 at every 0x34 RequestDownload request.
        Without this, multi-download logs (multiple 0x34 + 0x36 sequences) would
        cause false UDS-032 — the 0x01 starting the second download looks "wrong"
        to a counter that kept incrementing from the first download.

        Inputs per 0x36 frame:
          f.data[0] = 0x36 (SID)
          f.data[1] = blockSequenceCounter
          f.timestamp, f.line_no for reporting

        Also skips: any NRC 0x73 response frame that already confirms the ECU
        detected the error (avoids double-reporting).
        """
        # Build a merged, time-sorted list of 0x34 requests and 0x36 requests
        rd_reqs  = [f for f in self.frames if (f.service_id & 0xBF) == 0x34
                    and not f.is_response and not f.is_nrc]
        td_reqs  = [f for f in self.frames if (f.service_id & 0xBF) == 0x36
                    and not f.is_response and not f.is_nrc and len(f.data) >= 2]

        if not td_reqs:
            return

        # Timestamps of 0x34 requests — used to reset counter at each new download
        rd_timestamps = sorted(f.timestamp for f in rd_reqs)

        expected_seq    = 0x01
        prev_seq        = None
        prev_frame_ts   = -1.0   # timestamp of the previous 0x36 request

        for f in td_reqs:
            # Reset expected counter to 0x01 if a new 0x34 RequestDownload was
            # seen between the previous 0x36 and this one.
            # This handles multi-download logs where each 0x34 restarts at 0x01.
            if any(prev_frame_ts < rd_ts < f.timestamp for rd_ts in rd_timestamps):
                expected_seq = 0x01
                prev_seq     = None

            seq = f.data[1]

            # ISO 14229-1: server shall accept repeat of same counter (retry)
            if seq == prev_seq:
                prev_frame_ts = f.timestamp
                continue
            prev_seq      = seq
            prev_frame_ts = f.timestamp

            if seq != expected_seq:
                # Only report if no NRC 0x73 already received (ECU already flagged it)
                nrc73_already = any(
                    fr.is_nrc and fr.nrc_code == 0x73
                    and (fr.service_id & 0xBF) == 0x36
                    and fr.timestamp > f.timestamp
                    and fr.timestamp < f.timestamp + 2.0
                    for fr in self.frames
                )
                sev = "WARNING" if nrc73_already else "CRITICAL"
                self._add(Issue(
                    severity=sev, code="UDS-032",
                    title="Wrong Block Sequence Counter in TransferData",
                    description=(
                        f"TransferData block at t={f.timestamp:.3f}s has "
                        f"blockSequenceCounter=0x{seq:02X}, expected 0x{expected_seq:02X}. "
                        f"{'ECU confirmed NRC 0x73.' if nrc73_already else 'ECU will return NRC 0x73.'} "
                        f"Log line: {f.line_no}."
                    ),
                    timestamp=f.timestamp,
                    service="0x36 TransferData",
                    raw_data=f.data[:4].hex().upper(),
                    root_cause=(
                        f"Observed blockSequenceCounter=0x{seq:02X}, expected 0x{expected_seq:02X}.\n"
                        "Likely causes:\n"
                        "1. Counter not reset to 0x01 after a new 0x34 RequestDownload "
                        "(each download starts a fresh counter).\n"
                        "2. Incorrect rollover: rule is 0xFF → 0x00 → 0x01 "
                        "(per ISO 14229-1; 0x00 is a valid counter value after 0xFF).\n"
                        "3. Transfer restarted mid-sequence without issuing a new 0x34.\n"
                        "4. Counter incremented twice for one block (e.g. on retry path)."
                    ),
                    corrective_action=(
                        "1. Reset blockSequenceCounter = 0x01 after every 0x34 RequestDownload.\n"
                        "2. Rollover (ISO 14229-1): next = 0x00 if current == 0xFF else current + 1\n"
                        "   Sequence: 0x01 → ... → 0xFF → 0x00 → 0x01 → ...\n"
                        "3. On retry (no ECU response), resend with the SAME counter — do NOT increment.\n"
                        "4. Issue a new 0x34 before restarting a broken transfer."
                    ),
                    preventive_action=(
                        "• Reset counter variable in the same code path that sends 0x34.\n"
                        "• Unit-test rollover: 300 blocks, verify sequence crosses 0xFF→0x00→0x01.\n"
                        "• Separate retry logic clearly from normal increment path."
                    ),
                    line_no=f.line_no,
                ))
                # After a mismatch, resync expected to what ECU would expect next
                # (follow what was actually sent to stay in sync for subsequent blocks)
                seq_to_advance = seq
            else:
                seq_to_advance = expected_seq

            # Advance: 0xFF→0x00, 0x00→0x01, else +1
            if seq_to_advance == 0xFF:
                expected_seq = 0x00
            elif seq_to_advance == 0x00:
                expected_seq = 0x01
            else:
                expected_seq = seq_to_advance + 1
            prev_frame_ts = f.timestamp

    def _check_tester_present(self):
        """Detect missing TesterPresent during long operations.
        Only raised when a programming session was actually detected,
        because non-flash diagnostic sessions don't need TesterPresent.
        """
        has_prog = any(s.programming_session for s in self.sequences)
        has_transfer = any(s.transfer_frames > 0 or s.download_requested
                           for s in self.sequences)
        # If no programming session at all, TesterPresent is not required
        if not has_prog:
            return
        tp_frames = [f for f in self.frames if (f.service_id & 0xBF) == 0x3E and not f.is_response]
        if not tp_frames:
            self._add(Issue(
                severity="WARNING", code="UDS-040",
                title="TesterPresent (0x3E) Not Sent During Flash",
                description=(
                    "No TesterPresent frames detected in the log. "
                    "Without periodic 0x3E 80 (suppress response), "
                    "the ECU will drop the diagnostic session after S3 timeout (typically 5 s)."
                ),
                timestamp=None,
                service="0x3E TesterPresent",
                raw_data="3E 80",
                root_cause=(
                    "Flash tool not configured to send periodic TesterPresent. "
                    "Long operations (erase, check) can exceed S3 timeout."
                ),
                corrective_action=(
                    "1. Send 0x3E 80 (suppress positive response) every 2–3 s.\n"
                    "2. Enable TesterPresent in a background thread independent of transfer logic."
                ),
                preventive_action=(
                    "• Make periodic TesterPresent a mandatory background task in flash tool.\n"
                    "• Configure S3 timeout > erase time in ECU if modifiable."
                ),
            ))
        else:
            # Check for gaps > 4.5 s between TP frames
            nrc78_ts = [f.timestamp for f in self.frames
                        if f.is_nrc and f.nrc_code == 0x78]
            for i in range(1, len(tp_frames)):
                gap = tp_frames[i].timestamp - tp_frames[i-1].timestamp
                if gap > 4.5:
                    # Downgrade to INFO if the gap is covered by NRC 0x78 (responsePending)
                    # frames — ECU is actively processing (erase/check), and TP being
                    # suppressed during this window is expected behaviour, not an error.
                    gap_start = tp_frames[i-1].timestamp
                    gap_end   = tp_frames[i].timestamp
                    nrc78_in_gap = sum(1 for ts in nrc78_ts if gap_start <= ts <= gap_end)
                    covered_by_pending = nrc78_in_gap > 0
                    sev = "INFO" if covered_by_pending else "WARNING"
                    note = (f" ({nrc78_in_gap} NRC 0x78 pending responses in this gap — "
                            "ECU was actively processing; TesterPresent suppression is expected.)"
                            if covered_by_pending else "")
                    self._add(Issue(
                        severity=sev, code="UDS-041",
                        title=f"TesterPresent Gap {gap:.1f}s — Session May Have Timed Out",
                        description=(
                            f"TesterPresent gap of {gap:.1f}s detected between "
                            f"t={tp_frames[i-1].timestamp:.3f}s and t={tp_frames[i].timestamp:.3f}s. "
                            f"Default S3 server timeout is 5 s.{note}"
                        ),
                        timestamp=tp_frames[i-1].timestamp,
                        service="0x3E TesterPresent",
                        raw_data=f"Gap: {gap:.1f}s | NRC 0x78 in gap: {nrc78_in_gap}",
                        root_cause=(
                            f"TesterPresent gap of {gap:.1f}s detected. "
                            + (
                                "NRC 0x78 (responsePending) frames were present in this gap — "
                                "ECU was actively processing (erase/check). TP being delayed here "
                                "is expected behaviour; the session was maintained via pending responses."
                                if covered_by_pending else
                                "No NRC 0x78 frames in this gap. The ECU may have been responding to "
                                "other services (e.g. DSC probes, RDI) but TP was not sent by the tester. "
                                "If the ECU's S3 timer is 5s and this gap is 9s, the session may have "
                                "dropped and been silently re-established by the next DSC request."
                            )
                        ),
                        corrective_action=(
                            "1. Move TesterPresent sending to a dedicated background timer thread.\n"
                            "2. Use async/non-blocking architecture so TP is never blocked by "
                            "waiting for a response.\n"
                            + ("3. Session appears to have been maintained — verify with 0x50 03 "
                               "response following the gap." if not covered_by_pending else
                               "3. No corrective action needed — session was maintained via NRC 0x78.")
                        ),
                        preventive_action=(
                            "• Decouple TesterPresent from main flash logic using a background timer.\n"
                            "• Target TP interval of 2 s (< 5/2 of S3 timeout).\n"
                            "• Suppress TP-gap warnings when continuous NRC 0x78 stream is present."
                        ),
                        line_no=tp_frames[i].line_no,
                    ))
                    break

    def _check_comm_control(self):
        """Check if CommunicationControl (0x28) was used before flashing.
        Only raised when actual data transfer occurred (transfer_frames > 0),
        because comm control is only mandatory during active flash download.
        """
        cc_frames = [f for f in self.frames if (f.service_id & 0xBF) == 0x28]
        # Only flag when transfer was actually attempted
        has_transfer = any(seq.transfer_frames > 0 or seq.download_requested
                           for seq in self.sequences)
        if has_transfer and not cc_frames:
            self._add(Issue(
                severity="WARNING", code="UDS-042",
                title="CommunicationControl (0x28) Not Used",
                description=(
                    "Programming session detected but CommunicationControl (0x28) "
                    "disable-Rx/Tx was not sent. Unexpected bus traffic during "
                    "flashing can cause ISO-TP reassembly errors."
                ),
                timestamp=None,
                service="0x28 CommunicationControl",
                raw_data="28 03 01 (disable normal+NM comm)",
                root_cause=(
                    "Flash sequence does not include communication control steps. "
                    "Active periodic messages from other ECUs can interfere with "
                    "diagnostic message flow."
                ),
                corrective_action=(
                    "1. Send 0x28 03 01 before erasing/downloading.\n"
                    "2. Restore with 0x28 00 01 after ECU reset."
                ),
                preventive_action=(
                    "• Add CommunicationControl to flash sequence template.\n"
                    "• Verify bus is quiet during transfer by monitoring frame rate."
                ),
            ))

    def _check_dtc_setting(self):
        """Check if ControlDTCSetting (0x85) was disabled before flashing.
        Only raised when actual data transfer occurred.
        """
        dtc_frames = [f for f in self.frames if (f.service_id & 0xBF) == 0x85]
        has_transfer = any(seq.transfer_frames > 0 or seq.download_requested
                           for seq in self.sequences)
        if has_transfer and not dtc_frames:
            self._add(Issue(
                severity="INFO", code="UDS-043",
                title="ControlDTCSetting (0x85) Not Disabled Before Flash",
                description=(
                    "DTC setting was not disabled before programming. "
                    "Power supply or communication transients during flash "
                    "may generate false DTCs in the ECU."
                ),
                timestamp=None,
                service="0x85 ControlDTCSetting",
                raw_data="85 02 (disableDTCSetting)",
                root_cause=(
                    "Flash sequence does not disable DTC recording. "
                    "Voltage fluctuations during flash can trigger undervoltage or "
                    "communication DTCs that persist after flashing."
                ),
                corrective_action=(
                    "1. Send 0x85 02 (disableDTCSetting) before erasing.\n"
                    "2. Send 0x14 FF FF FF (ClearDTC) and 0x85 01 (enable) after reset."
                ),
                preventive_action=(
                    "• Add DTC control to flash sequence template.\n"
                    "• Always clear DTCs after successful flash and verify no new DTCs."
                ),
            ))

    def _check_response_pending_flood(self):
        """Detect excessive 0x78 RCRRP — sign of ECU overload."""
        pending = [f for f in self.frames if f.is_nrc and f.nrc_code == 0x78]
        if len(pending) > 10:
            self._add(Issue(
                severity="WARNING", code="UDS-044",
                title=f"Excessive ResponsePending (NRC 0x78) — {len(pending)} occurrences",
                description=(
                    f"{len(pending)} ResponsePending (RCRRP) frames received. "
                    "While normal for long operations, excessive pending suggests "
                    "ECU is heavily loaded or the operation is taking unexpectedly long."
                ),
                timestamp=pending[0].timestamp,
                service="NRC 0x78 requestCorrectlyReceivedResponsePending",
                raw_data=f"Count: {len(pending)}",
                root_cause=(
                    "1. ECU processing erase or check memory is taking longer than expected.\n"
                    "2. ECU flash driver is inefficient or not properly initialised.\n"
                    "3. Large memory block being erased/written in a single request."
                ),
                corrective_action=(
                    "1. Increase P2* timeout in tester to 30+ seconds for erase operations.\n"
                    "2. Split large blocks into smaller segments.\n"
                    "3. Check ECU specification for expected erase time and ensure supply voltage."
                ),
                preventive_action=(
                    "• Profile erase time during ECU bring-up and document in flash spec.\n"
                    "• Configure tester P2* based on measured worst-case erase time + 20% margin."
                ),
            ))

    def _check_wrong_session(self):
        """Detect programming-only services sent outside programming session.
        Uses sequence state rather than frame-level scan so passive sniffer
        logs (all Rx) work correctly.
        """
        prog_only = {0x34, 0x35, 0x36, 0x37}
        # Build a set of timestamps where programming was confirmed active
        prog_windows: List[tuple] = []
        for seq in self.sequences:
            if seq.programming_session and seq.session_start:
                end = seq.session_end or (seq.session_start + 3600)
                prog_windows.append((seq.session_start, end))

        def in_prog_window(ts: float) -> bool:
            return any(s <= ts <= e for s, e in prog_windows)

        for f in self.frames:
            sid = f.service_id & 0xBF
            if sid in prog_only and not f.is_response and not in_prog_window(f.timestamp):
                self._add(Issue(
                    severity="ERROR", code="UDS-050",
                    title=f"Service 0x{sid:02X} Sent Outside Programming Session",
                    description=(
                        f"Service 0x{sid:02X} ({UDS_SERVICES.get(sid,'?')}) was sent at "
                        f"t={f.timestamp:.3f}s but no active programming session was detected."
                    ),
                    timestamp=f.timestamp,
                    service=f"0x{sid:02X} {UDS_SERVICES.get(sid,'?')}",
                    raw_data=f.data.hex().upper(),
                    root_cause=(
                        "Flash tool state machine error — programming session was not established "
                        "or confirmation was not received before proceeding."
                    ),
                    corrective_action=(
                        "1. Verify 0x10 02 positive response before calling any programming service.\n"
                        "2. Check flash tool state machine tracks session state correctly."
                    ),
                    preventive_action=(
                        "• Enforce session state machine: block prog services until session confirmed.\n"
                        "• Add assertion in flash tool: assert(current_session == PROGRAMMING)."
                    ),
                    line_no=f.line_no,
                ))

    def _check_data_integrity(self):
        """Check for 0x36 blocks with zero-length data payload.
        A valid 0x36 frame must have: SID(1) + blockCounter(1) + data(>=1) = min 3 bytes.
        len(f.data)==2 means SID+blockCounter only — no actual flash data.
        """
        td_frames = [f for f in self.frames
                     if (f.service_id & 0xBF) == 0x36 and not f.is_response]
        for f in td_frames:
            if len(f.data) < 3:   # FIX: was <= 2 which is same threshold
                self._add(Issue(
                    severity="ERROR", code="UDS-060",
                    title="TransferData Block with No Payload",
                    description=(
                        f"TransferData frame at t={f.timestamp:.3f}s contains "
                        "only the service ID and block counter — no actual data. "
                        "This will cause a flash write failure."
                    ),
                    timestamp=f.timestamp,
                    service="0x36 TransferData",
                    raw_data=f.data.hex().upper(),
                    root_cause=(
                        "Flash tool sent an empty TransferData block, likely due to "
                        "a file parser bug, incorrect block size calculation, or "
                        "reading past end of the flash image."
                    ),
                    corrective_action=(
                        "1. Validate that all TransferData blocks have data length > 0.\n"
                        "2. Check flash image file is not truncated.\n"
                        "3. Verify block size calculation against maxBlockLength from 0x34 response."
                    ),
                    preventive_action=(
                        "• Add assertion: assert(len(block_data) > 0) before sending 0x36.\n"
                        "• Validate entire flash image before starting the sequence."
                    ),
                    line_no=f.line_no,
                ))

    def _check_sequence_order(self):
        """Detect if ECU reset was called before transfer exit.
        Only relevant when a download was actually requested.
        """
        # Don't flag if no download was ever requested
        any_download = any(s.download_requested or s.transfer_frames > 0
                           for s in self.sequences)
        if not any_download:
            return
        reset_frames = [f for f in self.frames
                        if (f.service_id & 0xBF) == 0x11 and not f.is_response]
        exit_frames  = [f for f in self.frames
                        if (f.service_id & 0xBF) == 0x37]
        if reset_frames and not exit_frames:
            self._add(Issue(
                severity="ERROR", code="UDS-070",
                title="ECUReset Before RequestTransferExit",
                description=(
                    "ECUReset (0x11) was detected but no RequestTransferExit (0x37) "
                    "was found. Resetting before completing the transfer may corrupt flash."
                ),
                timestamp=reset_frames[0].timestamp,
                service="0x11 ECUReset",
                raw_data="11 01",
                root_cause=(
                    "Flash sequence ended abnormally (timeout, error, operator abort) "
                    "and ECU was reset without properly closing the data transfer."
                ),
                corrective_action=(
                    "1. Always send 0x37 and receive positive response before 0x11.\n"
                    "2. Add error recovery sequence: if any critical failure, send 0x37 then 0x11."
                ),
                preventive_action=(
                    "• Implement cleanup sequence on error: ensure 0x37 is always called.\n"
                    "• Use try/finally pattern in flash tool code to guarantee 0x37."
                ),
                line_no=reset_frames[0].line_no,
            ))

    def _add(self, issue: Issue):
        # Deduplicate:
        # - UDS-030 (timeout) dedup by (code, service) so different services each get one entry
        # - All other codes dedup by code alone (one entry per issue type)
        if issue.code == "UDS-030":
            if not any(i.code == issue.code and i.service == issue.service
                       for i in self.issues):
                self.issues.append(issue)
        else:
            if not any(i.code == issue.code for i in self.issues):
                self.issues.append(issue)


# ═══════════════════════════════════════════════════════════════════════════════
# PDF REPORT GENERATOR
# ═══════════════════════════════════════════════════════════════════════════════
class PDFReportGenerator:
    # Brand colours
    RED     = colors.HexColor("#c0392b")
    ORANGE  = colors.HexColor("#e67e22")
    AMBER   = colors.HexColor("#f39c12")
    BLUE    = colors.HexColor("#2980b9")
    GREEN   = colors.HexColor("#27ae60")
    DARK    = colors.HexColor("#1a1a2e")
    MED     = colors.HexColor("#16213e")
    LIGHT   = colors.HexColor("#0f3460")
    WHITE   = colors.white
    LGRAY   = colors.HexColor("#f4f4f4")
    MGRAY   = colors.HexColor("#cccccc")
    DGRAY   = colors.HexColor("#555555")
    TEAL    = colors.HexColor("#1abc9c")
    CYAN    = colors.HexColor("#0097a7")
    PURPLE  = colors.HexColor("#7b1fa2")

    SEV_COLORS = {
        "CRITICAL": colors.HexColor("#c0392b"),
        "ERROR":    colors.HexColor("#e67e22"),
        "WARNING":  colors.HexColor("#f39c12"),
        "INFO":     colors.HexColor("#2980b9"),
    }

    def __init__(self, issues: List[Issue], sequences: List[FlashSequence],
                 uds_frames: List[UDSFrame], can_msgs: List[CANMsg],
                 log_path: str, resp_times: List[Dict] = None):
        self.issues     = issues
        self.sequences  = sequences
        self.frames     = uds_frames
        self.can_msgs   = can_msgs
        self.log_path   = log_path
        self.resp_times = resp_times or []
        self._styles    = self._build_styles()

    def _build_styles(self) -> Dict:
        base = getSampleStyleSheet()
        def ps(name, **kw):
            return ParagraphStyle(name, parent=base['Normal'], **kw)

        return {
            "title":      ps("rpt_title",   fontSize=24, fontName="Helvetica-Bold",
                              textColor=self.WHITE, alignment=TA_CENTER, spaceAfter=6),
            "subtitle":   ps("rpt_sub",     fontSize=12, fontName="Helvetica",
                              textColor=self.TEAL, alignment=TA_CENTER, spaceAfter=4),
            "meta":       ps("rpt_meta",    fontSize=9,  fontName="Helvetica",
                              textColor=self.MGRAY, alignment=TA_CENTER),
            "h1":         ps("rpt_h1",      fontSize=16, fontName="Helvetica-Bold",
                              textColor=self.DARK, spaceBefore=16, spaceAfter=6),
            "h2":         ps("rpt_h2",      fontSize=13, fontName="Helvetica-Bold",
                              textColor=self.LIGHT, spaceBefore=12, spaceAfter=4),
            "h3":         ps("rpt_h3",      fontSize=11, fontName="Helvetica-Bold",
                              textColor=self.DGRAY, spaceBefore=8, spaceAfter=3),
            "body":       ps("rpt_body",    fontSize=9,  fontName="Helvetica",
                              textColor=self.DARK, spaceAfter=4, leading=14),
            "body_b":     ps("rpt_body_b",  fontSize=9,  fontName="Helvetica-Bold",
                              textColor=self.DARK, spaceAfter=3),
            "code":       ps("rpt_code",    fontSize=8,  fontName="Courier",
                              textColor=self.DGRAY, backColor=self.LGRAY,
                              spaceAfter=3, leading=12),
            "bullet":     ps("rpt_bullet",  fontSize=9,  fontName="Helvetica",
                              textColor=self.DARK, leftIndent=14, spaceAfter=2,
                              leading=14),
            "caption":    ps("rpt_cap",     fontSize=8,  fontName="Helvetica",
                              textColor=self.DGRAY, alignment=TA_CENTER, spaceAfter=4),
            "sev_crit":   ps("sev_crit",    fontSize=9,  fontName="Helvetica-Bold",
                              textColor=self.WHITE, backColor=self.RED,
                              alignment=TA_CENTER),
            "sev_err":    ps("sev_err",     fontSize=9,  fontName="Helvetica-Bold",
                              textColor=self.WHITE, backColor=self.ORANGE,
                              alignment=TA_CENTER),
            "sev_warn":   ps("sev_warn",    fontSize=9,  fontName="Helvetica-Bold",
                              textColor=self.DARK, backColor=self.AMBER,
                              alignment=TA_CENTER),
            "sev_info":   ps("sev_info",    fontSize=9,  fontName="Helvetica-Bold",
                              textColor=self.WHITE, backColor=self.BLUE,
                              alignment=TA_CENTER),
        }

    @staticmethod
    def _esc(text) -> str:
        """Escape XML special chars so ReportLab paraparser never sees raw < > & ' "."""
        s = str(text) if text is not None else ""
        # Replace & first (must be first to avoid double-escaping)
        s = s.replace("&", "&amp;")
        s = s.replace("<", "&lt;")
        s = s.replace(">", "&gt;")
        return s

    def P(self, text: str, style: str = "body") -> Paragraph:
        return Paragraph(self._esc(text), self._styles[style])

    def generate(self, out_path: str):
        doc = SimpleDocTemplate(
            out_path, pagesize=A4,
            leftMargin=15*mm, rightMargin=15*mm,
            topMargin=10*mm, bottomMargin=15*mm,
            title="UDS Flash RCA Report",
            author="CANvas UDS Flash Analyzer",
        )
        story = []
        story += self._cover_page()
        story.append(PageBreak())
        story += self._executive_summary()
        story += self._flash_sequence_overview()
        story += self._issue_table()
        story += self._detailed_findings()
        story += self._corrective_preventive()
        story += self._session_ladder()          # NEW
        story += self._latency_analysis()        # NEW
        story += self._security_access_deep()    # NEW
        story += self._ecu_identity()            # NEW
        story += self._bus_load_analysis()       # NEW
        story += self._uds_timeline()
        story += self._appendix()
        doc.build(story, onFirstPage=self._page_header_footer,
                  onLaterPages=self._page_header_footer)

    # ── cover page ─────────────────────────────────────────────────────────────
    def _cover_page(self) -> list:
        story = []
        # Dark banner
        banner_data = [["", "", ""]]
        banner = Table(banner_data, colWidths=[180*mm], rowHeights=[55*mm])
        banner.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,-1), self.DARK),
        ]))
        story.append(banner)

        # Title overlay (use spacer + paragraph trick)
        story.append(Spacer(1, -50*mm))
        story.append(self.P("UDS Flash Log Analyzer", "title"))
        story.append(self.P("Root Cause Analysis Report", "subtitle"))
        story.append(self.P(
            f"Generated: {datetime.now().strftime('%Y-%m-%d  %H:%M:%S')}",
            "meta"))
        story.append(Spacer(1, 10*mm))

        # Summary stats cards
        c_count = sum(1 for i in self.issues if i.severity == "CRITICAL")
        e_count = sum(1 for i in self.issues if i.severity == "ERROR")
        w_count = sum(1 for i in self.issues if i.severity == "WARNING")
        i_count = sum(1 for i in self.issues if i.severity == "INFO")
        # Flash outcome for cover page banner
        _any_exit = any(s.transfer_exit_ok for s in self.sequences)
        _any_prog = any(s.programming_session for s in self.sequences)
        _any_dl   = any(s.download_requested or s.transfer_frames > 0
                        for s in self.sequences)

        def stat_cell(label, count, col):
            return [Paragraph(f"<b>{count}</b>",
                               ParagraphStyle("sc", fontSize=28, fontName="Helvetica-Bold",
                                              textColor=col, alignment=TA_CENTER)),
                    Paragraph(label,
                               ParagraphStyle("sl", fontSize=9, fontName="Helvetica",
                                              textColor=self.DGRAY, alignment=TA_CENTER))]

        cards = Table([
            [stat_cell("CRITICAL", c_count, self.RED),
             stat_cell("ERROR",    e_count, self.ORANGE),
             stat_cell("WARNING",  w_count, self.AMBER),
             stat_cell("INFO",     i_count, self.BLUE)],
        ], colWidths=[45*mm]*4, rowHeights=[22*mm])
        cards.setStyle(TableStyle([
            ("BOX",          (0,0), (-1,-1), 0.5, self.MGRAY),
            ("INNERGRID",    (0,0), (-1,-1), 0.5, self.MGRAY),
            ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
            ("BACKGROUND",   (0,0), (0,-1), colors.HexColor("#fdf3f2")),
            ("BACKGROUND",   (1,0), (1,-1), colors.HexColor("#fdf6f0")),
            ("BACKGROUND",   (2,0), (2,-1), colors.HexColor("#fdfaf0")),
            ("BACKGROUND",   (3,0), (3,-1), colors.HexColor("#f0f7fd")),
        ]))
        story.append(cards)
        story.append(Spacer(1, 8*mm))

        # Log file info
        info_rows = [
            ["Log File",      os.path.basename(self.log_path)],
            ["Total Frames",  str(len(self.can_msgs))],
            ["UDS Frames",    str(len(self.frames))],
            ["Flash Sequences", str(len(self.sequences))],
            ["Total Issues",  str(len(self.issues))],
            ["Report Date",   datetime.now().strftime("%Y-%m-%d %H:%M")],
        ]
        info_tbl = Table(info_rows, colWidths=[50*mm, 130*mm])
        info_tbl.setStyle(TableStyle([
            ("FONT",         (0,0), (-1,-1), "Helvetica", 9),
            ("FONT",         (0,0), (0,-1), "Helvetica-Bold", 9),
            ("TEXTCOLOR",    (0,0), (0,-1), self.DGRAY),
            ("TEXTCOLOR",    (1,0), (1,-1), self.DARK),
            ("ROWBACKGROUNDS",(0,0),(-1,-1), [self.LGRAY, self.WHITE]),
            ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
            ("TOPPADDING",   (0,0), (-1,-1), 5),
            ("BOTTOMPADDING",(0,0), (-1,-1), 5),
            ("LEFTPADDING",  (0,0), (-1,-1), 8),
            ("BOX",          (0,0), (-1,-1), 0.5, self.MGRAY),
            ("INNERGRID",    (0,0), (-1,-1), 0.3, self.MGRAY),
        ]))
        story.append(info_tbl)
        return story

    # ── executive summary ─────────────────────────────────────────────────────
    def _executive_summary(self) -> list:
        story = [self.P("1. Executive Summary", "h1"),
                 HRFlowable(width="100%", thickness=1, color=self.TEAL)]

        c     = sum(1 for i in self.issues if i.severity == "CRITICAL")
        e     = sum(1 for i in self.issues if i.severity == "ERROR")
        w     = sum(1 for i in self.issues if i.severity == "WARNING")
        total = len(self.issues)

        # ── Verdict based on ACTUAL flash sequence outcome ────────────────────
        # Primary: did any sequence complete (transfer exit confirmed)?
        any_exit    = any(s.transfer_exit_ok   for s in self.sequences)
        any_prog    = any(s.programming_session for s in self.sequences)
        any_sa      = any(s.security_access_ok  for s in self.sequences)
        any_dl      = any(s.download_requested  for s in self.sequences)
        any_transfer= any(s.transfer_frames > 0 for s in self.sequences)

        # Determine verdict from sequence state first, then refine with issues
        if not self.sequences:
            # No programming session detected at all
            verdict     = "NO FLASH SEQUENCE DETECTED"
            verdict_col = self.DGRAY
        elif any_exit:
            # Transfer completed — verdict is PASSED unless critical issues
            # that indicate actual flash corruption (0x72, 0x73 NRCs)
            corrupt_nrcs = {0x72, 0x73}
            has_corruption = any(
                i.severity == "CRITICAL" and
                any(nrc in i.raw_data for nrc in ["0x72","0x73","NRC 0x72","NRC 0x73"])
                for i in self.issues
            )
            if has_corruption:
                verdict     = "FLASH FAILED — MEMORY CORRUPTION"
                verdict_col = self.RED
            elif w > 0 or e > 0:
                verdict     = "FLASH PASSED WITH WARNINGS"
                verdict_col = self.AMBER
            else:
                verdict     = "FLASH PASSED"
                verdict_col = self.GREEN
        elif any_dl or any_transfer:
            # Download started but never completed
            verdict     = "FLASH INCOMPLETE — TRANSFER NOT COMPLETED"
            verdict_col = self.ORANGE
        elif any_sa:
            # Security OK but download never started
            verdict     = "FLASH FAILED — DOWNLOAD NEVER STARTED"
            verdict_col = self.RED
        elif any_prog:
            # Programming session entered but security failed
            verdict     = "FLASH FAILED — SECURITY ACCESS FAILED"
            verdict_col = self.RED
        else:
            # Programming session requested but never confirmed
            verdict     = "FLASH FAILED — SESSION NOT ESTABLISHED"
            verdict_col = self.RED

        v_tbl = Table([[Paragraph(verdict,
                                   ParagraphStyle("v", fontSize=16,
                                                  fontName="Helvetica-Bold",
                                                  textColor=self.WHITE,
                                                  alignment=TA_CENTER))]],
                      colWidths=[180*mm], rowHeights=[14*mm])
        v_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,-1), verdict_col),
            ("VALIGN",     (0,0), (-1,-1), "MIDDLE"),
        ]))
        story += [Spacer(1, 4*mm), v_tbl, Spacer(1, 4*mm)]

        seq_count = len(self.sequences)
        prog_ok   = sum(1 for s in self.sequences if s.programming_session)
        sa_ok     = sum(1 for s in self.sequences if s.security_access_ok)
        tx_ok     = sum(1 for s in self.sequences if s.transfer_exit_ok)
        total_tf  = sum(s.transfer_frames for s in self.sequences)

        summary_text = (
            f"Analysis of the provided CAN log identified <b>{total} issue(s)</b>: "
            f"<b><font color='#c0392b'>{c} CRITICAL</font></b>, "
            f"<b><font color='#e67e22'>{e} ERROR</font></b>, "
            f"<b><font color='#f39c12'>{w} WARNING</font></b>, "
            f"and <b>{total - c - e - w} INFO</b>.  "
            f"<b>{seq_count}</b> flash sequence(s) detected. "
            f"<b>{prog_ok}</b> reached programming session. "
            f"<b>{sa_ok}</b> passed security access. "
            f"<b>{tx_ok}</b> completed transfer exit. "
            f"Total transfer blocks: <b>{total_tf}</b>."
        )
        story.append(Paragraph(
            summary_text,
            ParagraphStyle("sum", fontSize=10, fontName="Helvetica",
                           textColor=self.DARK, spaceAfter=6, leading=16)))

        # ── Per-sequence plain-English outcome ───────────────────────────────
        if self.sequences:
            story.append(Spacer(1, 3*mm))
            story.append(self.P("Flash Sequence Results", "h3"))
            for i, s in enumerate(self.sequences, 1):
                # Determine per-sequence outcome
                if s.transfer_exit_ok and s.security_access_ok and s.programming_session:
                    seq_result   = "✓  COMPLETED SUCCESSFULLY"
                    seq_col      = self.GREEN
                    seq_detail   = (f"{s.transfer_frames} data blocks transferred, "
                                    f"transfer exit confirmed.")
                    if not s.check_ok:
                        seq_result = "✓  COMPLETED (no integrity check)"
                        seq_col    = self.AMBER
                        seq_detail += " Post-flash integrity check (0x31 CheckMemory) not detected."
                elif s.download_requested or s.transfer_frames > 0:
                    seq_result = "✗  INCOMPLETE — TRANSFER NOT FINISHED"
                    seq_col    = self.ORANGE
                    seq_detail = (f"{s.transfer_frames} block(s) transferred, "
                                  "but RequestTransferExit (0x37) was not confirmed.")
                elif s.security_access_ok:
                    seq_result = "✗  FAILED — DOWNLOAD NEVER STARTED"
                    seq_col    = self.RED
                    seq_detail = "Security access passed but no RequestDownload (0x34) was sent."
                elif s.programming_session:
                    seq_result = "✗  FAILED — SECURITY ACCESS NOT COMPLETED"
                    seq_col    = self.RED
                    seq_detail = "Programming session entered but security access did not succeed."
                else:
                    seq_result = "✗  FAILED — PROGRAMMING SESSION NOT ESTABLISHED"
                    seq_col    = self.RED
                    seq_detail = "No positive response to DiagnosticSessionControl (0x10 02) received."

                dur_str = f"{s.duration:.1f}s" if s.duration else "—"
                ecu_str = f"0x{s.ecu_address:X}" if s.ecu_address else "—"
                start_str = f"{s.session_start:.3f}s" if s.session_start else "—"

                seq_rows = [
                    [Paragraph(f"Sequence {i}", ParagraphStyle(
                        "sn", fontSize=10, fontName="Helvetica-Bold",
                        textColor=self.WHITE)),
                     Paragraph(seq_result, ParagraphStyle(
                        "sr", fontSize=10, fontName="Helvetica-Bold",
                        textColor=self.WHITE))],
                ]
                seq_hdr = Table(seq_rows, colWidths=[35*mm, 145*mm])
                seq_hdr.setStyle(TableStyle([
                    ("BACKGROUND", (0,0), (-1,-1), seq_col),
                    ("VALIGN",     (0,0), (-1,-1), "MIDDLE"),
                    ("TOPPADDING", (0,0), (-1,-1), 5),
                    ("BOTTOMPADDING", (0,0), (-1,-1), 5),
                    ("LEFTPADDING",   (0,0), (-1,-1), 8),
                ]))

                detail_rows = [
                    ["ECU Address", ecu_str,      "Session Start", start_str],
                    ["Duration",    dur_str,       "Transfer Blocks", str(s.transfer_frames)],
                    ["Prog Session", "YES" if s.programming_session else "NO",
                     "Security Access", "YES" if s.security_access_ok else "NO"],
                    ["Erase OK",    "YES" if s.erase_ok else "NO",
                     "Transfer Exit", "YES" if s.transfer_exit_ok else "NO"],
                ]
                detail_p_rows = []
                for row in detail_rows:
                    detail_p_rows.append([
                        Paragraph(row[0], ParagraphStyle("dk", fontSize=8, fontName="Helvetica-Bold",
                                                          textColor=self.DGRAY)),
                        Paragraph(row[1], ParagraphStyle("dv", fontSize=8, fontName="Helvetica",
                                                          textColor=self.DARK)),
                        Paragraph(row[2], ParagraphStyle("dk2", fontSize=8, fontName="Helvetica-Bold",
                                                          textColor=self.DGRAY)),
                        Paragraph(row[3], ParagraphStyle("dv2", fontSize=8, fontName="Helvetica",
                                                          textColor=self.DARK)),
                    ])
                detail_tbl = Table(detail_p_rows, colWidths=[35*mm, 55*mm, 40*mm, 50*mm])
                detail_tbl.setStyle(TableStyle([
                    ("ROWBACKGROUNDS", (0,0), (-1,-1), [self.LGRAY, self.WHITE]),
                    ("TOPPADDING",     (0,0), (-1,-1), 4),
                    ("BOTTOMPADDING",  (0,0), (-1,-1), 4),
                    ("LEFTPADDING",    (0,0), (-1,-1), 6),
                    ("BOX",            (0,0), (-1,-1), 0.5, self.MGRAY),
                    ("INNERGRID",      (0,0), (-1,-1), 0.3, self.MGRAY),
                ]))

                note_para = Paragraph(seq_detail,
                                      ParagraphStyle("sd", fontSize=9, fontName="Helvetica",
                                                     textColor=self.DGRAY,
                                                     leftIndent=4, spaceAfter=4, leading=13))
                story.append(KeepTogether([
                    Spacer(1, 2*mm), seq_hdr, detail_tbl, note_para
                ]))

        return story

    # ── flash sequence overview ────────────────────────────────────────────────
    def _flash_sequence_overview(self) -> list:
        if not self.sequences:
            return []
        story = [Spacer(1,4*mm), self.P("2. Flash Sequence Overview", "h1"),
                 HRFlowable(width="100%", thickness=1, color=self.TEAL)]
        hdrs = ["#", "Session Start", "Duration", "Prog Session",
                "Sec Access", "Erase", "Transfer Blocks", "Exit", "ECU Addr"]
        rows = [hdrs]
        for i, s in enumerate(self.sequences, 1):
            def yesno(v, yes_col=self.GREEN, no_col=self.RED):
                col = yes_col if v else no_col
                txt = "YES" if v else "NO"
                return Paragraph(f"<b>{txt}</b>",
                                  ParagraphStyle("yn", fontSize=8, fontName="Helvetica-Bold",
                                                 textColor=self.WHITE, backColor=col,
                                                 alignment=TA_CENTER))
            rows.append([
                str(i),
                f"{s.session_start:.3f}s" if s.session_start else "—",
                f"{s.duration:.2f}s",
                yesno(s.programming_session),
                yesno(s.security_access_ok),
                yesno(s.erase_ok),
                str(s.transfer_frames),
                yesno(s.transfer_exit_ok),
                f"0x{s.ecu_address:03X}" if s.ecu_address else "—",
            ])
        col_w = [10*mm, 25*mm, 22*mm, 25*mm, 22*mm, 18*mm, 24*mm, 18*mm, 22*mm]
        tbl = Table(rows, colWidths=col_w)
        tbl.setStyle(TableStyle([
            ("BACKGROUND",   (0,0), (-1,0), self.DARK),
            ("TEXTCOLOR",    (0,0), (-1,0), self.WHITE),
            ("FONT",         (0,0), (-1,0), "Helvetica-Bold", 8),
            ("FONT",         (0,1), (-1,-1), "Helvetica", 8),
            ("ROWBACKGROUNDS",(0,1),(-1,-1), [self.WHITE, self.LGRAY]),
            ("ALIGN",        (0,0), (-1,-1), "CENTER"),
            ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
            ("TOPPADDING",   (0,0), (-1,-1), 5),
            ("BOTTOMPADDING",(0,0), (-1,-1), 5),
            ("BOX",          (0,0), (-1,-1), 0.5, self.MGRAY),
            ("INNERGRID",    (0,0), (-1,-1), 0.3, self.MGRAY),
        ]))
        story.append(tbl)
        return story

    # ── issue summary table ────────────────────────────────────────────────────
    def _issue_table(self) -> list:
        story = [Spacer(1,4*mm), self.P("3. Issue Summary", "h1"),
                 HRFlowable(width="100%", thickness=1, color=self.TEAL)]
        if not self.issues:
            story.append(self.P("No issues detected. Flash sequence appears complete.", "body"))
            return story
        hdrs = ["Code", "Severity", "Service", "Title", "Timestamp"]
        rows = [hdrs]
        for issue in self.issues:
            sev_style = f"sev_{issue.severity.lower()}"
            rows.append([
                Paragraph(self._esc(issue.code), ParagraphStyle("ic", fontSize=7, fontName="Courier",
                                                      textColor=self.DGRAY)),
                Paragraph(self._esc(issue.severity), self._styles.get(sev_style, self._styles["body"])),
                Paragraph(self._esc(issue.service[:28]),
                           ParagraphStyle("is", fontSize=7, fontName="Helvetica",
                                          textColor=self.DGRAY)),
                Paragraph(self._esc(issue.title[:50]),
                           ParagraphStyle("it", fontSize=8, fontName="Helvetica",
                                          textColor=self.DARK)),
                Paragraph(f"{issue.timestamp:.3f}s" if issue.timestamp else "—",
                           ParagraphStyle("its", fontSize=7, fontName="Courier",
                                          textColor=self.DGRAY, alignment=TA_CENTER)),
            ])
        col_w = [18*mm, 22*mm, 38*mm, 80*mm, 22*mm]
        tbl = Table(rows, colWidths=col_w)
        tbl.setStyle(TableStyle([
            ("BACKGROUND",   (0,0), (-1,0), self.DARK),
            ("TEXTCOLOR",    (0,0), (-1,0), self.WHITE),
            ("FONT",         (0,0), (-1,0), "Helvetica-Bold", 8),
            ("ROWBACKGROUNDS",(0,1),(-1,-1), [self.WHITE, self.LGRAY]),
            ("ALIGN",        (0,0), (-1,0), "CENTER"),
            ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
            ("TOPPADDING",   (0,0), (-1,-1), 4),
            ("BOTTOMPADDING",(0,0), (-1,-1), 4),
            ("BOX",          (0,0), (-1,-1), 0.5, self.MGRAY),
            ("INNERGRID",    (0,0), (-1,-1), 0.3, self.MGRAY),
        ]))
        story.append(tbl)
        return story

    # ── detailed findings ─────────────────────────────────────────────────────
    def _detailed_findings(self) -> list:
        story = [PageBreak(), self.P("4. Detailed Findings", "h1"),
                 HRFlowable(width="100%", thickness=1, color=self.TEAL)]
        for idx, issue in enumerate(self.issues, 1):
            sev_col = self.SEV_COLORS.get(issue.severity, self.BLUE)
            title_tbl = Table([[
                Paragraph(self._esc(issue.severity),
                           ParagraphStyle("st", fontSize=9, fontName="Helvetica-Bold",
                                          textColor=self.WHITE, alignment=TA_CENTER)),
                Paragraph(self._esc(f"{issue.code} — {issue.title}"),
                           ParagraphStyle("htitle", fontSize=11, fontName="Helvetica-Bold",
                                          textColor=self.DARK)),
            ]], colWidths=[22*mm, 158*mm])
            title_tbl.setStyle(TableStyle([
                ("BACKGROUND",  (0,0),(0,-1), sev_col),
                ("BACKGROUND",  (1,0),(1,-1), colors.HexColor("#f0f4f8")),
                ("VALIGN",      (0,0),(-1,-1),"MIDDLE"),
                ("TOPPADDING",  (0,0),(-1,-1), 6),
                ("BOTTOMPADDING",(0,0),(-1,-1), 6),
                ("LEFTPADDING", (1,0),(1,-1), 10),
            ]))
            rows = []

            def info_row(label, content, mono=False):
                font = "Courier" if mono else "Helvetica"
                return [
                    Paragraph(label, ParagraphStyle("il", fontSize=8, fontName="Helvetica-Bold",
                                                     textColor=self.DGRAY, alignment=TA_RIGHT)),
                    Paragraph(self._esc(content),
                               ParagraphStyle("iv", fontSize=8, fontName=font,
                                              textColor=self.DARK, leading=13)),
                ]

            detail_rows = [
                ["Label", "Content"],
            ]
            detail_rows += [
                info_row("Service:", issue.service),
                info_row("Timestamp:", f"{issue.timestamp:.3f}s" if issue.timestamp else "—"),
                info_row("Raw Data:", issue.raw_data, mono=True),
                info_row("Description:", issue.description),
            ]
            if issue.line_no:
                detail_rows.append(info_row("Log Line:", str(issue.line_no)))

            detail_tbl = Table(detail_rows[1:], colWidths=[30*mm, 150*mm])
            detail_tbl.setStyle(TableStyle([
                ("FONT",         (0,0), (-1,-1), "Helvetica", 8),
                ("ROWBACKGROUNDS",(0,0),(-1,-1), [self.WHITE, self.LGRAY]),
                ("VALIGN",       (0,0), (-1,-1), "TOP"),
                ("TOPPADDING",   (0,0), (-1,-1), 4),
                ("BOTTOMPADDING",(0,0), (-1,-1), 4),
                ("LEFTPADDING",  (0,0), (0,-1), 6),
                ("LEFTPADDING",  (1,0), (1,-1), 8),
                ("BOX",          (0,0), (-1,-1), 0.5, self.MGRAY),
                ("INNERGRID",    (0,0), (-1,-1), 0.3, self.MGRAY),
            ]))

            # RC / CA / PA blocks
            rc_block  = self._three_col_block("Root Cause Analysis", issue.root_cause, self.RED)
            ca_block  = self._three_col_block("Corrective Action",   issue.corrective_action, self.ORANGE)
            pa_block  = self._three_col_block("Preventive Action",   issue.preventive_action, self.GREEN)

            story.append(KeepTogether([
                Spacer(1, 6*mm),
                title_tbl,
                detail_tbl,
                rc_block, ca_block, pa_block,
            ]))
        return story

    def _three_col_block(self, label: str, content: str, color) -> Table:
        lines = [l.strip() for l in content.split("\n") if l.strip()]
        items = []
        for line in lines:
            # bullet or numbered — escape XML special chars before Paragraph parsing
            if re.match(r"^[\d]+\.", line) or line.startswith("•"):
                safe = self._esc(line.lstrip("•0123456789. ").strip())
                items.append(Paragraph(f"• {safe}",
                                        ParagraphStyle("bi", fontSize=8, fontName="Helvetica",
                                                       textColor=self.DARK, leftIndent=8, leading=13)))
            else:
                items.append(Paragraph(self._esc(line),
                                        ParagraphStyle("nb", fontSize=8, fontName="Helvetica",
                                                       textColor=self.DARK, leading=13)))
        from reportlab.platypus import KeepInFrame
        header = Paragraph(label,
                           ParagraphStyle("bh", fontSize=8, fontName="Helvetica-Bold",
                                          textColor=self.WHITE, alignment=TA_CENTER))
        tbl = Table([[header], [items or [Paragraph("—", ParagraphStyle("z", fontSize=8))]]],
                    colWidths=[180*mm])
        tbl.setStyle(TableStyle([
            ("BACKGROUND",   (0,0), (-1,0), color),
            ("BACKGROUND",   (0,1), (-1,-1), colors.HexColor("#fafafa")),
            ("BOX",          (0,0), (-1,-1), 0.5, self.MGRAY),
            ("TOPPADDING",   (0,0), (-1,-1), 5),
            ("BOTTOMPADDING",(0,0), (-1,-1), 5),
            ("LEFTPADDING",  (0,1), (-1,-1), 10),
        ]))
        return tbl

    # ── corrective / preventive summary ───────────────────────────────────────
    def _corrective_preventive(self) -> list:
        story = [PageBreak(), self.P("5. Consolidated Corrective & Preventive Actions", "h1"),
                 HRFlowable(width="100%", thickness=1, color=self.TEAL),
                 Spacer(1, 3*mm)]
        critical_issues = [i for i in self.issues if i.severity in ("CRITICAL","ERROR")]
        if critical_issues:
            story.append(self.P("5.1  Immediate Actions Required (CRITICAL / ERROR)", "h2"))
            for issue in critical_issues:
                story.append(self.P(f"[{issue.code}] {issue.title}", "body_b"))
                for line in issue.corrective_action.split("\n"):
                    if line.strip():
                        story.append(Paragraph(f"• {self._esc(line.strip().lstrip('•0123456789. '))}",
                                                self._styles["bullet"]))
            story.append(Spacer(1, 4*mm))

        story.append(self.P("5.2  Long-Term Preventive Actions", "h2"))
        # Deduplicate PAs
        all_pa = []
        seen = set()
        for issue in self.issues:
            for line in issue.preventive_action.split("\n"):
                l = line.strip().lstrip("•. ").strip()
                if l and l not in seen:
                    seen.add(l)
                    all_pa.append((issue.severity, l))
        for sev, pa in all_pa[:25]:   # max 25 unique
            col = SEVERITY_COLORS.get(sev, C["text"])
            safe_pa = self._esc(pa)   # escape < > & in action text before XML parse
            story.append(Paragraph(
                f"<font color='{col}'>[{sev}]</font>  {safe_pa}",
                ParagraphStyle("pab", fontSize=9, fontName="Helvetica",
                               textColor=self.DARK, leftIndent=10, spaceAfter=3, leading=14)))
        return story

    # ── UDS timeline ──────────────────────────────────────────────────────────
    def _uds_timeline(self) -> list:
        story = [PageBreak(), self.P("6. UDS Frame Timeline", "h1"),
                 HRFlowable(width="100%", thickness=1, color=self.TEAL),
                 Spacer(1, 2*mm)]
        if not self.frames:
            story.append(self.P("No UDS frames detected.", "body"))
            return story
        hdrs = ["Timestamp", "Dir", "Src ID", "Service", "Sub-Func", "NRC", "Raw (first 8B)"]
        rows = [hdrs]
        for f in self.frames[:200]:   # limit to first 200
            nrc_txt = UDS_NRC.get(f.nrc_code, f"0x{f.nrc_code:02X}") if f.is_nrc else ""
            rows.append([
                f"{f.timestamp:.3f}s",
                "RSP" if f.is_response else "REQ",
                f"0x{f.src_id:03X}",
                f"0x{f.service_id:02X} {f.service_name[:16]}",
                f"0x{f.sub_func:02X}" if f.sub_func is not None else "—",
                nrc_txt[:14] if nrc_txt else "—",
                f.data[:8].hex().upper(),
            ])
        col_w = [22*mm, 14*mm, 16*mm, 46*mm, 18*mm, 28*mm, 36*mm]
        tbl = Table(rows, colWidths=col_w)
        tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0), self.DARK),
            ("TEXTCOLOR",     (0,0), (-1,0), self.WHITE),
            ("FONT",          (0,0), (-1,0), "Helvetica-Bold", 7),
            ("FONT",          (0,1), (-1,-1), "Courier", 7),
            ("ROWBACKGROUNDS",(0,1),(-1,-1), [self.WHITE, self.LGRAY]),
            ("ALIGN",         (0,0), (-1,-1), "CENTER"),
            ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
            ("TOPPADDING",    (0,0), (-1,-1), 3),
            ("BOTTOMPADDING", (0,0), (-1,-1), 3),
            ("BOX",           (0,0), (-1,-1), 0.5, self.MGRAY),
            ("INNERGRID",     (0,0), (-1,-1), 0.3, self.MGRAY),
        ]))
        # Highlight NRC rows
        for r, f in enumerate(self.frames[:200], 1):
            if f.is_nrc:
                bg = colors.HexColor("#fdf3f2") if f.nrc_code != 0x78 else colors.HexColor("#f0f7fd")
                tbl.setStyle(TableStyle([("BACKGROUND", (0,r),(-1,r), bg)]))
        story.append(tbl)
        if len(self.frames) > 200:
            story.append(self.P(f"... {len(self.frames)-200} additional frames not shown.", "caption"))
        return story

    # ── NEW: Session Ladder Diagram ───────────────────────────────────────────
    def _session_ladder(self) -> list:
        story = [PageBreak(),
                 self.P("7. UDS Session Ladder Diagram", "h1"),
                 HRFlowable(width="100%", thickness=1, color=self.TEAL),
                 Spacer(1, 2*mm)]
        if not self.frames:
            story.append(self.P("No UDS frames to display.", "body"))
            return story

        story.append(self.P(
            "Sequence diagram showing request/response pairs with timing. "
            "Each arrow shows direction (→ request, ← response). "
            "NRC frames highlighted in red.", "body"))
        story.append(Spacer(1, 2*mm))

        # Identify tester and ECU addresses
        ids = sorted(set(f.src_id for f in self.frames))
        tester_id = min(ids) if ids else 0
        ecu_id    = max(ids) if len(ids) > 1 else (ids[0] + 8 if ids else 0)

        tester_lbl = f"Tester\n0x{tester_id:X}"
        ecu_lbl    = f"ECU\n0x{ecu_id:X}"

        ladder_rows = [[
            Paragraph(tester_lbl, ParagraphStyle("tl", fontSize=8,
                       fontName="Helvetica-Bold", textColor=self.TEAL,
                       alignment=TA_CENTER)),
            Paragraph("Time", ParagraphStyle("tl2", fontSize=7,
                       fontName="Helvetica", textColor=self.DGRAY,
                       alignment=TA_CENTER)),
            Paragraph("Service", ParagraphStyle("tl3", fontSize=7,
                       fontName="Helvetica", textColor=self.DGRAY,
                       alignment=TA_CENTER)),
            Paragraph(ecu_lbl, ParagraphStyle("tl4", fontSize=8,
                       fontName="Helvetica-Bold", textColor=self.ORANGE,
                       alignment=TA_CENTER)),
        ]]

        for f in self.frames[:80]:
            sid = f.service_id & 0xBF
            sname = UDS_SERVICES.get(sid, f"0x{sid:02X}")
            sub_str = f" (sub=0x{f.sub_func:02X})" if f.sub_func is not None else ""
            ts_str  = f"{f.timestamp:.3f}s"
            nrc_str = f" NRC=0x{f.nrc_code:02X}" if f.is_nrc else ""

            if f.is_nrc:
                svc_text = (f"✗ NRC 0x{f.nrc_code:02X}: "
                            f"{UDS_NRC.get(f.nrc_code,'?')[:20]}")
                txt_col  = self.RED
            elif f.is_response:
                svc_text = f"✓ {sname}{sub_str}"[:40]
                txt_col  = self.GREEN
            else:
                svc_text = f"→ {sname}{sub_str}"[:40]
                txt_col  = self.DARK

            svc_para = Paragraph(svc_text,
                                  ParagraphStyle("sp", fontSize=7,
                                                 fontName="Helvetica",
                                                 textColor=txt_col))
            ts_para  = Paragraph(ts_str,
                                  ParagraphStyle("tp", fontSize=7,
                                                 fontName="Courier",
                                                 textColor=self.DGRAY,
                                                 alignment=TA_CENTER))

            if not f.is_response:
                row = [Paragraph("⟶", ParagraphStyle("arr", fontSize=10,
                                                       fontName="Helvetica",
                                                       textColor=self.TEAL,
                                                       alignment=TA_RIGHT)),
                       ts_para, svc_para, Paragraph("", ParagraphStyle("e", fontSize=7))]
            else:
                row = [Paragraph("", ParagraphStyle("e2", fontSize=7)),
                       ts_para, svc_para,
                       Paragraph("⟵", ParagraphStyle("arr2", fontSize=10,
                                                       fontName="Helvetica",
                                                       textColor=self.ORANGE,
                                                       alignment=TA_LEFT))]
            ladder_rows.append(row)

        col_w = [20*mm, 22*mm, 110*mm, 22*mm]
        tbl = Table(ladder_rows, colWidths=col_w)
        style = [
            ("BACKGROUND",   (0,0), (-1,0), self.DARK),
            ("TEXTCOLOR",    (0,0), (-1,0), self.WHITE),
            ("ROWBACKGROUNDS",(0,1),(-1,-1), [self.WHITE, self.LGRAY]),
            ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
            ("TOPPADDING",   (0,0), (-1,-1), 3),
            ("BOTTOMPADDING",(0,0), (-1,-1), 3),
            ("BOX",          (0,0), (-1,-1), 0.5, self.MGRAY),
            ("INNERGRID",    (0,0), (-1,-1), 0.3, self.MGRAY),
        ]
        # Highlight NRC rows
        for r, f in enumerate(self.frames[:80], 1):
            if f.is_nrc:
                style.append(("BACKGROUND", (0,r), (-1,r),
                               colors.HexColor("#fdf3f2")))
        tbl.setStyle(TableStyle(style))
        story.append(tbl)
        if len(self.frames) > 80:
            story.append(self.P(
                f"... {len(self.frames)-80} additional frames not shown.", "caption"))
        return story

    # ── NEW: Request-Response Latency Analysis ─────────────────────────────────
    def _latency_analysis(self) -> list:
        story = [Spacer(1, 4*mm),
                 self.P("8. Request-Response Latency Analysis", "h1"),
                 HRFlowable(width="100%", thickness=1, color=self.TEAL),
                 Spacer(1, 2*mm)]

        story.append(self.P(
            "Latency = time from tester request to first ECU response (each response "
            "consumed once — no duplicate pairings). "
            "Req/Rsp columns show: CAN ID on first line + abbreviated time (SS:mmmm) on second line. "
            "Full HH:MM:SS:mmmm timestamps are in Section 6 (UDS Frame Timeline). "
            "P2max = 50ms  |  P2*max = 5000ms  |  Status: ✓OK <50ms, ~WARN <1s, ✗SLOW <5s, ✗P2*! >5s.", "body"))
        story.append(Spacer(1, 2*mm))

        # Use pre-built resp_times (already correctly paired, one-to-one)
        if not self.resp_times:
            story.append(self.P("No matched request/response pairs found.", "body"))
            return story

        # ── Smart filtering: collapse repetitive rows into summaries ─────────
        # 0x36 TransferData: show summary only (block count, min/max/avg latency)
        # 0x31 RoutineControl same RID repeated: collapse to one summary row
        td_pairs   = [r for r in self.resp_times if r["sid"] == 0x36]
        non_td     = [r for r in self.resp_times if r["sid"] != 0x36]

        # Build summary for TransferData
        td_summary = {}   # (req_can_id, rsp_can_id) → stats
        for r in td_pairs:
            key = (r.get("req_can_id","?"), r.get("rsp_can_id","?"))
            if key not in td_summary:
                td_summary[key] = {"lats": [], "nrc": [], "first": r}
            td_summary[key]["lats"].append(r["delta_ms"])
            if r["is_nrc"]:
                td_summary[key]["nrc"].append(r["nrc_code"])

        # Collapse repeated 0x31 RoutineControl rows for same RID (req_data[:8])
        # Keep first+last, add summary in between if > 3 consecutive identical
        collapsed_non_td = []
        i = 0
        while i < len(non_td):
            r = non_td[i]
            if r["sid"] == 0x31:
                # Find run of same req_data (same RID)
                j = i
                while (j < len(non_td) and
                       non_td[j]["sid"] == 0x31 and
                       non_td[j].get("req_data","")[:8] == r.get("req_data","")[:8]):
                    j += 1
                run_len = j - i
                if run_len > 3:
                    collapsed_non_td.append(non_td[i])   # first
                    # Insert summary row as a special marker
                    lats = [non_td[k]["delta_ms"] for k in range(i, j)]
                    collapsed_non_td.append({
                        "__summary__": True,
                        "service": f"RoutineControl (×{run_len} repeats)",
                        "sub":     r.get("sub",""),
                        "req_data": r.get("req_data","")[:8],
                        "rsp_data": non_td[j-1].get("rsp_data","")[:8],
                        "req_can_id": r.get("req_can_id",""),
                        "rsp_can_id": r.get("rsp_can_id",""),
                        "req_log_ts": r.get("req_log_ts",""),
                        "rsp_log_ts": non_td[j-1].get("rsp_log_ts",""),
                        "delta_ms": sum(lats)/len(lats),
                        "lat_min":  min(lats),
                        "lat_max":  max(lats),
                        "is_nrc":   False, "nrc_code": 0,
                        "sid": 0x31,
                    })
                    collapsed_non_td.append(non_td[j-1])  # last
                    i = j
                    continue
            collapsed_non_td.append(r)
            i += 1

        def make_remark(rt: dict) -> tuple:
            """Return (remark_text, remark_colour) — kept short for 30mm column."""
            ms      = rt["delta_ms"]
            is_nrc  = rt["is_nrc"]
            nrc     = rt["nrc_code"]
            if is_nrc and nrc == 0x78:
                return ("0x78 pending — normal", self.BLUE)
            if is_nrc:
                nrc_name = UDS_NRC.get(nrc, f"?")
                return (f"NRC 0x{nrc:02X} {nrc_name[:16]}", self.RED)
            if ms < 50:
                return ("OK within P2", self.GREEN)
            if ms < 1000:
                return (f"OK within P2* ({ms:.0f}ms)", self.GREEN)
            if ms < 5000:
                return (f"Slow {ms:.0f}ms (<P2*)", self.AMBER)
            return (f"EXCEEDED P2* {ms:.0f}ms", self.RED)

        def status_col(ms, is_nrc, nrc):
            if is_nrc and nrc != 0x78:  return (f"NRC\n0x{nrc:02X}", self.RED)
            if ms < 50:                  return ("✓ OK",               self.GREEN)
            if ms < 1000:                return ("~WARN",              self.AMBER)
            if ms < 5000:                return ("✗ SLOW",             self.ORANGE)
            return                              ("✗ P2*!",             self.RED)

        # ── Summary stats ────────────────────────────────────────────────────
        ok_lats = [r["delta_ms"] for r in self.resp_times
                   if not (r["is_nrc"] and r["nrc_code"] != 0x78)]
        if ok_lats:
            story.append(self.P(
                f"Latency summary: min={min(ok_lats):.1f}ms  "
                f"max={max(ok_lats):.1f}ms  "
                f"avg={sum(ok_lats)/len(ok_lats):.1f}ms  "
                f"pairs={len(ok_lats)}", "body_b"))
        story.append(Spacer(1, 1*mm))

        # ── Table: split into pages of 40 rows to avoid overflow ─────────────
        # Columns: Service | Sub | Req CAN ID | Req Time (Log) | Req Data (8B)
        #        | Rsp CAN ID | Rsp Time (Log) | Rsp Data (8B) | Latency | Status | Remark
        # ── Compact 9-col table fitting A4 portrait 180mm usable width ─────────
        # Col: Service(30)|Sub(8)|ReqCAN+SS:mmmm(26)|ReqData(19)|RspCAN+SS:mmmm(26)|RspData(19)|Lat(11)|Status(15)|Remark(24)
        # Total = 178mm ✓  (page usable = 210-15-15 = 180mm)
        FONT_SZ = 6.8
        # Col widths (A4 portrait usable = 210-15-15 = 180mm):
        # Service(32)|Sub(7)|ReqCANT(25)|ReqData(18)|RspCANT(25)|RspData(18)|Lat(12)|Stat(13)|Remark(30)
        # Total = 180mm ✓  Status 13mm fits "✓ OK", "~WARN", "✗SLOW", "NRC\n0x31"
        col_w9 = [32*mm, 7*mm, 25*mm, 18*mm, 25*mm, 18*mm, 12*mm, 13*mm, 30*mm]  # sum=180mm

        def make_para(txt, size=None, font="Helvetica", col=None, align=TA_LEFT):
            c = col or self.DARK
            sz = size or FONT_SZ
            return Paragraph(self._esc(txt),
                              ParagraphStyle("lp", fontSize=sz, fontName=font,
                                             textColor=c, alignment=align, leading=sz + 1.5))

        def ts_short(ts_str):
            """HH:MM:SS:mmmm → SS:mmmm to save column space."""
            if ts_str and ts_str != "—":
                parts = ts_str.split(":")
                if len(parts) >= 4:
                    return f"{parts[2]}:{parts[3]}"
            return ts_str or "—"

        hdrs9 = ["Service", "Sub",
                 "Req CAN ID + Time\n(SS:mmmm)", "Req Data\n(8B)",
                 "Rsp CAN ID + Time\n(SS:mmmm)", "Rsp Data\n(8B)",
                 "Lat\n(ms)", "Stat", "Remark"]

        rows_data = collapsed_non_td
        PAGE_ROWS = 45

        for chunk_start in range(0, len(rows_data), PAGE_ROWS):
            chunk = rows_data[chunk_start: chunk_start + PAGE_ROWS]

            tbl_rows = [[
                make_para(h, size=6.5, font="Helvetica-Bold", col=self.WHITE, align=TA_CENTER)
                for h in hdrs9
            ]]

            for rt in chunk:
                # ── Collapsed summary row ────────────────────────────────────
                if rt.get("__summary__"):
                    lat_avg = rt["delta_ms"]
                    ss, scol = (("✓ OK", self.GREEN) if lat_avg < 50 else
                                ("~WARN", self.AMBER) if lat_avg < 1000 else
                                ("✗SLOW", self.ORANGE))
                    req_ct  = f"{rt.get('req_can_id','')[:13]}\n{ts_short(rt.get('req_log_ts',''))}"
                    rsp_ct  = f"{rt.get('rsp_can_id','')[:13]}\n…{ts_short(rt.get('rsp_log_ts',''))}"
                    n_rep   = rt["service"].split("×")[1].split(" ")[0] if "×" in rt["service"] else "?"
                    tbl_rows.append([
                        make_para(rt["service"].split(" (×")[0][:22],
                                  font="Helvetica-Bold", col=colors.HexColor("#1a5276")),
                        make_para(rt.get("sub","—"), font="Courier", col=self.DGRAY, align=TA_CENTER),
                        make_para(req_ct, font="Courier", col=colors.HexColor("#2980b9"), align=TA_CENTER),
                        make_para(rt.get("req_data","—"), font="Courier",
                                  col=colors.HexColor("#e67e22"), align=TA_CENTER),
                        make_para(rsp_ct, font="Courier", col=colors.HexColor("#2980b9"), align=TA_CENTER),
                        make_para(rt.get("rsp_data","—"), font="Courier",
                                  col=colors.HexColor("#27ae60"), align=TA_CENTER),
                        make_para(f"avg\n{lat_avg:.0f}\nmin{rt.get('lat_min',0):.0f}\nmax{rt.get('lat_max',0):.0f}",
                                  font="Courier-Bold", col=scol, align=TA_RIGHT),
                        make_para(ss, font="Helvetica-Bold", col=scol, align=TA_CENTER),
                        make_para(f"×{n_rep} repeats — all normal", col=self.DGRAY),
                    ])
                    continue

                ms      = rt["delta_ms"]
                is_nrc  = rt["is_nrc"]
                nrc     = rt["nrc_code"]
                status, scol = status_col(ms, is_nrc, nrc)
                remark, rcol = make_remark(rt)
                nrc_suf  = f"\nNRC 0x{nrc:02X}" if is_nrc and nrc != 0x78 else ""
                req_ct   = f"{rt.get('req_can_id','—')[:13]}\n{ts_short(rt.get('req_log_ts','—'))}"
                rsp_ct   = f"{rt.get('rsp_can_id','—')[:13]}\n{ts_short(rt.get('rsp_log_ts','—'))}"
                tbl_rows.append([
                    make_para(rt["service"][:22], col=self.RED if is_nrc else self.DARK),
                    make_para(rt.get("sub","—"), font="Courier", col=self.DGRAY, align=TA_CENTER),
                    make_para(req_ct,  font="Courier", col=colors.HexColor("#2980b9"), align=TA_CENTER),
                    make_para(rt.get("req_data","—"), font="Courier",
                              col=colors.HexColor("#e67e22"), align=TA_CENTER),
                    make_para(rsp_ct + nrc_suf, font="Courier",
                              col=self.RED if is_nrc else colors.HexColor("#2980b9"),
                              align=TA_CENTER),
                    make_para(rt.get("rsp_data","—"), font="Courier",
                              col=self.RED if is_nrc else colors.HexColor("#27ae60"),
                              align=TA_CENTER),
                    make_para(f"{ms:.1f}", font="Courier-Bold", col=scol, align=TA_RIGHT),
                    make_para(status, font="Helvetica-Bold", col=scol, align=TA_CENTER),
                    make_para(remark[:40], col=rcol),
                ])

            tbl = Table(tbl_rows, colWidths=col_w9, repeatRows=1)
            tbl.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, 0), self.DARK),
                ("ROWBACKGROUNDS",(0, 1), (-1,-1), [self.WHITE, self.LGRAY]),
                ("VALIGN",        (0, 0), (-1,-1), "MIDDLE"),
                ("TOPPADDING",    (0, 0), (-1,-1), 2),
                ("BOTTOMPADDING", (0, 0), (-1,-1), 2),
                ("BOX",           (0, 0), (-1,-1), 0.4, self.MGRAY),
                ("INNERGRID",     (0, 0), (-1,-1), 0.2, self.MGRAY),
            ]))
            for row_idx, rt in enumerate(chunk, 1):
                if rt.get("is_nrc") and rt.get("nrc_code", 0) != 0x78:
                    tbl.setStyle(TableStyle([
                        ("BACKGROUND", (0, row_idx), (-1, row_idx),
                         colors.HexColor("#fdf3f2"))
                    ]))
            story.append(tbl)
            if chunk_start + PAGE_ROWS < len(rows_data):
                story.append(PageBreak())


        # ── TransferData Summary Section ─────────────────────────────────
        if td_summary:
            story.append(Spacer(1, 4*mm))
            story.append(self.P("TransferData (0x36) Block Transfer Summary", "h2"))
            story.append(self.P(
                "Individual 0x36 blocks are collapsed here to keep the report concise. "
                "Each row below represents one complete download segment "
                "(one RequestDownload → N blocks → RequestTransferExit).", "body"))
            td_hdr_rows = [["Tester CAN ID", "ECU CAN ID", "Block Count",
                             "Latency Min (ms)", "Latency Avg (ms)", "Latency Max (ms)",
                             "NRC Count", "Assessment"]]
            for (req_id, rsp_id), stats in td_summary.items():
                lats    = stats["lats"]
                nrc_cnt = len(stats["nrc"])
                avg_ms  = sum(lats) / len(lats) if lats else 0
                max_ms  = max(lats) if lats else 0
                # Assessment
                if nrc_cnt > 0:
                    assess = f"⚠ {nrc_cnt} NRC(s) in transfer"
                    a_col  = self.ORANGE
                elif max_ms > 5000:
                    assess = f"✗ Block(s) exceeded P2* ({max_ms:.0f}ms max)"
                    a_col  = self.RED
                elif avg_ms > 1000:
                    assess = f"~ Avg latency high ({avg_ms:.0f}ms)"
                    a_col  = self.AMBER
                else:
                    assess = f"✓ All blocks within P2* (avg {avg_ms:.0f}ms)"
                    a_col  = self.GREEN

                def tp(t, col=None, font="Courier", size=8):
                    return Paragraph(self._esc(t),
                                     ParagraphStyle("td", fontSize=size, fontName=font,
                                                    textColor=col or self.DARK,
                                                    alignment=TA_CENTER))
                td_hdr_rows.append([
                    tp(req_id, col=colors.HexColor("#2980b9")),
                    tp(rsp_id, col=colors.HexColor("#2980b9")),
                    tp(str(len(lats))),
                    tp(f"{min(lats):.1f}", col=self.GREEN if min(lats)<1000 else self.AMBER),
                    tp(f"{avg_ms:.1f}",    col=self.GREEN if avg_ms <1000 else self.AMBER),
                    tp(f"{max_ms:.1f}",    col=self.GREEN if max_ms <5000 else self.RED),
                    tp(str(nrc_cnt),       col=self.RED if nrc_cnt > 0 else self.GREEN),
                    Paragraph(assess, ParagraphStyle("ta", fontSize=8, fontName="Helvetica-Bold",
                                                     textColor=a_col, leading=11)),
                ])

            td_tbl = Table(td_hdr_rows,
                           colWidths=[25*mm, 25*mm, 18*mm, 22*mm, 22*mm, 22*mm, 16*mm, 50*mm])
            td_tbl.setStyle(TableStyle([
                ("BACKGROUND",    (0,0), (-1,0), self.DARK),
                ("TEXTCOLOR",     (0,0), (-1,0), self.WHITE),
                ("FONT",          (0,0), (-1,0), "Helvetica-Bold", 8),
                ("ROWBACKGROUNDS",(0,1), (-1,-1), [self.WHITE, self.LGRAY]),
                ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
                ("TOPPADDING",    (0,0), (-1,-1), 4),
                ("BOTTOMPADDING", (0,0), (-1,-1), 4),
                ("BOX",           (0,0), (-1,-1), 0.5, self.MGRAY),
                ("INNERGRID",     (0,0), (-1,-1), 0.3, self.MGRAY),
            ]))
            story.append(td_tbl)

        total_omitted = len(self.resp_times) - len(collapsed_non_td)
        if total_omitted > 0:
            story.append(self.P(
                f"Note: {total_omitted} TransferData block pairs summarised in the section above.",
                "caption"))
        return story

    # ── NEW: Security Access Deep Analysis ────────────────────────────────────
    def _security_access_deep(self) -> list:
        story = [Spacer(1, 4*mm),
                 self.P("9. Security Access Deep Analysis", "h1"),
                 HRFlowable(width="100%", thickness=1, color=self.TEAL),
                 Spacer(1, 2*mm)]

        sa_frames = [f for f in self.frames
                     if (f.service_id & 0xBF) == 0x27]
        if not sa_frames:
            story.append(self.P("No SecurityAccess (0x27) frames found.", "body"))
            return story

        # Group into seed/key pairs
        seed_reqs  = [f for f in sa_frames if not f.is_response and not f.is_nrc
                      and f.sub_func is not None and (f.sub_func & 0x01) == 0x01]
        key_reqs   = [f for f in sa_frames if not f.is_response and not f.is_nrc
                      and f.sub_func is not None and (f.sub_func & 0x01) == 0x00
                      and f.sub_func != 0]
        seed_resps = [f for f in sa_frames if f.is_response and not f.is_nrc
                      and f.sub_func is not None and (f.sub_func & 0x01) == 0x01]
        nrc_frames = [f for f in sa_frames if f.is_nrc]

        # Proprietary sub-function detection (non-standard: not 0x01/0x02/..)
        std_sa_subs  = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
        prop_frames  = [f for f in sa_frames
                        if f.sub_func is not None and f.sub_func not in std_sa_subs
                        and f.sub_func not in {0x7F}]

        rows = [["Aspect", "Value", "Assessment"]]

        def row(aspect, value, assess, assess_col=None):
            col = assess_col or self.DARK
            return [
                Paragraph(aspect, ParagraphStyle("sa_a", fontSize=8,
                           fontName="Helvetica-Bold", textColor=self.DGRAY)),
                Paragraph(str(value), ParagraphStyle("sa_v", fontSize=8,
                           fontName="Courier", textColor=self.DARK)),
                Paragraph(str(assess), ParagraphStyle("sa_r", fontSize=8,
                           fontName="Helvetica", textColor=col)),
            ]

        rows.append(row("Total SA Frames", len(sa_frames), "All frames counted"))
        rows.append(row("Seed Requests", len(seed_reqs),
                        "OK" if seed_reqs else "Missing", self.GREEN if seed_reqs else self.RED))
        rows.append(row("Seed Responses", len(seed_resps),
                        "OK" if seed_resps else "No seed received", self.GREEN if seed_resps else self.RED))
        rows.append(row("Key Send Requests", len(key_reqs),
                        "OK" if key_reqs else "Key never sent", self.GREEN if key_reqs else self.RED))
        nrc_detail = ", ".join(
            "0x{:02X}({})".format(f.nrc_code, UDS_NRC.get(f.nrc_code, "?")[:12])
            for f in nrc_frames[:3])
        rows.append(row("NRC on SA", len(nrc_frames),
                        "NONE" if not nrc_frames else "FAILED: " + nrc_detail,
                        self.GREEN if not nrc_frames else self.RED))

        # Sub-function levels
        sub_levels = sorted(set(f.sub_func for f in sa_frames if f.sub_func is not None))
        rows.append(row("Sub-Function Levels Used",
                        ", ".join(f"0x{s:02X}" for s in sub_levels),
                        "Standard (0x01/0x02)" if all(s in std_sa_subs for s in sub_levels)
                        else f"PROPRIETARY detected: {', '.join(f'0x{s:02X}' for s in sub_levels if s not in std_sa_subs)}",
                        self.GREEN if all(s in std_sa_subs for s in sub_levels) else self.AMBER))

        # Seed values
        for i, sr in enumerate(seed_resps[:3], 1):
            seed_bytes = sr.data[2:] if len(sr.data) > 2 else b''
            seed_hex   = seed_bytes.hex().upper()
            rows.append(row(f"Seed #{i} Value",
                            f"0x{seed_hex}" if seed_hex else "—",
                            f"Length={len(seed_bytes)} bytes"))

        # Seed-to-key timing
        for seed_r in seed_resps:
            matching_key = next(
                (f for f in key_reqs
                 if f.timestamp > seed_r.timestamp
                 and f.timestamp < seed_r.timestamp + 30.0),
                None)
            if matching_key:
                delay = matching_key.timestamp - seed_r.timestamp
                status = ("✓ OK" if delay < 2.0 else
                          "⚠ SLOW" if delay < 5.0 else
                          "✗ TIMEOUT RISK")
                col = self.GREEN if delay < 2.0 else (self.AMBER if delay < 5.0 else self.RED)
                rows.append(row(f"Seed→Key Delay",
                                f"{delay*1000:.1f} ms  ({delay:.3f} s)",
                                status, col))

        # Key results
        for kq in key_reqs[:3]:
            key_bytes = kq.data[2:] if len(kq.data) > 2 else b''
            rows.append(row(f"Key Sent (sub=0x{kq.sub_func:02X})",
                            f"0x{key_bytes.hex().upper()}" if key_bytes else "(empty)",
                            "Key value logged"))

        tbl = Table(rows, colWidths=[50*mm, 60*mm, 65*mm])
        tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0), self.DARK),
            ("TEXTCOLOR",     (0,0), (-1,0), self.WHITE),
            ("FONT",          (0,0), (-1,0), "Helvetica-Bold", 8),
            ("ROWBACKGROUNDS",(0,1),(-1,-1), [self.WHITE, self.LGRAY]),
            ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
            ("TOPPADDING",    (0,0), (-1,-1), 5),
            ("BOTTOMPADDING", (0,0), (-1,-1), 5),
            ("BOX",           (0,0), (-1,-1), 0.5, self.MGRAY),
            ("INNERGRID",     (0,0), (-1,-1), 0.3, self.MGRAY),
        ]))
        story.append(tbl)

        # Recommendation box
        if prop_frames:
            rec = (
                f"⚠ Proprietary SecurityAccess sub-functions detected "
                f"({', '.join(f'0x{f.sub_func:02X}' for f in prop_frames[:5])}). "
                "Standard UDS uses 0x01 (request seed) and 0x02 (send key). "
                "Verify that the seed-key DLL/algorithm matches this ECU's "
                "proprietary sub-function numbering scheme exactly."
            )
            rec_tbl = Table([[Paragraph(rec,
                                         ParagraphStyle("rt", fontSize=8,
                                                        fontName="Helvetica",
                                                        textColor=self.DARK,
                                                        leading=13))]],
                             colWidths=[175*mm])
            rec_tbl.setStyle(TableStyle([
                ("BACKGROUND",   (0,0),(-1,-1), colors.HexColor("#fdf6f0")),
                ("BOX",          (0,0),(-1,-1), 1.0, self.ORANGE),
                ("TOPPADDING",   (0,0),(-1,-1), 6),
                ("BOTTOMPADDING",(0,0),(-1,-1), 6),
                ("LEFTPADDING",  (0,0),(-1,-1), 8),
            ]))
            story.append(Spacer(1, 4*mm))
            story.append(rec_tbl)
        return story

    # ── NEW: ECU Identity Information ─────────────────────────────────────────
    def _ecu_identity(self) -> list:
        story = [Spacer(1, 4*mm),
                 self.P("10. ECU Identity & DID Information", "h1"),
                 HRFlowable(width="100%", thickness=1, color=self.TEAL),
                 Spacer(1, 2*mm)]

        # Known DID names (ISO 14229-1 + common OEM)
        KNOWN_DIDS = {
            0xF180: "BootSoftwareIdentification",
            0xF181: "ApplicationSoftwareIdentification",
            0xF182: "ApplicationDataIdentification",
            0xF183: "BootSoftwareFingerprint",
            0xF184: "ApplicationSoftwareFingerprint",
            0xF185: "ApplicationDataFingerprint",
            0xF186: "ActiveDiagnosticSession",
            0xF187: "VehicleManufacturerSparePartNumber",
            0xF188: "VehicleManufacturerECUSoftwareNumber",
            0xF189: "VehicleManufacturerECUSoftwareVersionNumber",
            0xF18A: "SystemSupplierIdentifier",
            0xF18B: "ECUManufacturingDate",
            0xF18C: "ECUSerialNumber",
            0xF18D: "SupportedFunctionalUnits",
            0xF18E: "VehicleManufacturerKitAssemblyPartNumber",
            0xF190: "VIN",
            0xF191: "VehicleManufacturerECUHardwareNumber",
            0xF192: "SystemSupplierECUHardwareNumber",
            0xF193: "SystemSupplierECUHardwareVersionNumber",
            0xF194: "SystemSupplierECUSoftwareNumber",
            0xF195: "SystemSupplierECUSoftwareVersionNumber",
            0xF196: "ExhaustRegulationOrTypeApproval",
            0xF197: "SystemNameOrEngineType",
            0xF198: "RepairShopCode",
            0xF199: "ProgrammingDate",
            0xF19D: "ECUInstallationDate",
            0xF19E: "ODXFile",
            0xF1A0: "StatusOfSupplierBootSoftware",
        }

        rdbi_frames = [f for f in self.frames
                       if (f.service_id & 0xBF) == 0x22]
        rdbi_resps  = [f for f in self.frames
                       if (f.service_id & 0xBF) == 0x22 and f.is_response
                       and not f.is_nrc]

        if not rdbi_frames:
            story.append(self.P(
                "No ReadDataByIdentifier (0x22) frames found in log.", "body"))
            return story

        story.append(self.P(
            f"Found {len(rdbi_frames)} RDBI frames "
            f"({len(rdbi_resps)} positive responses).", "body"))
        story.append(Spacer(1, 2*mm))

        did_rows = [["DID", "Name", "Value (Hex)", "Value (ASCII)"]]
        seen_dids: set = set()

        for f in rdbi_resps:
            if len(f.data) < 3:
                continue
            # Response: 62 DID_H DID_L data...
            did = (f.data[1] << 8) | f.data[2]
            if did in seen_dids:
                continue
            seen_dids.add(did)
            raw_val = f.data[3:]
            # Strip padding (0xAA common in BusMaster)
            stripped = bytes(b for b in raw_val if b != 0xAA)
            val_hex  = raw_val.hex().upper() if raw_val else "—"
            try:
                val_ascii = stripped.decode("ascii", errors="replace").strip()
                val_ascii = "".join(c if c.isprintable() else "." for c in val_ascii)
            except Exception:
                val_ascii = "—"

            did_name = KNOWN_DIDS.get(did, f"DID_0x{did:04X}")
            did_rows.append([
                Paragraph(f"0x{did:04X}",
                           ParagraphStyle("di", fontSize=8, fontName="Courier",
                                          textColor=self.CYAN, alignment=TA_CENTER)),
                Paragraph(did_name[:30],
                           ParagraphStyle("dn", fontSize=8, fontName="Helvetica",
                                          textColor=self.DARK)),
                Paragraph(val_hex[:24],
                           ParagraphStyle("dv", fontSize=7, fontName="Courier",
                                          textColor=self.AMBER)),
                Paragraph(val_ascii[:20] if val_ascii else "—",
                           ParagraphStyle("da", fontSize=8, fontName="Helvetica",
                                          textColor=self.DGRAY)),
            ])

        if len(did_rows) <= 1:
            story.append(self.P(
                "No readable DID response data found.", "body"))
            return story

        col_w = [18*mm, 64*mm, 52*mm, 40*mm]
        tbl = Table(did_rows, colWidths=col_w)
        tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0), self.DARK),
            ("TEXTCOLOR",     (0,0), (-1,0), self.WHITE),
            ("FONT",          (0,0), (-1,0), "Helvetica-Bold", 8),
            ("ROWBACKGROUNDS",(0,1),(-1,-1), [self.WHITE, self.LGRAY]),
            ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
            ("TOPPADDING",    (0,0), (-1,-1), 4),
            ("BOTTOMPADDING", (0,0), (-1,-1), 4),
            ("BOX",           (0,0), (-1,-1), 0.5, self.MGRAY),
            ("INNERGRID",     (0,0), (-1,-1), 0.3, self.MGRAY),
        ]))
        story.append(tbl)
        return story

    # ── NEW: Bus Load Analysis ─────────────────────────────────────────────────
    def _bus_load_analysis(self) -> list:
        story = [Spacer(1, 4*mm),
                 self.P("11. Bus Load & Frame Count Validation", "h1"),
                 HRFlowable(width="100%", thickness=1, color=self.TEAL),
                 Spacer(1, 2*mm)]

        if not self.can_msgs:
            story.append(self.P("No CAN frames available.", "body"))
            return story

        total  = len(self.can_msgs)
        t_min  = min(m.timestamp for m in self.can_msgs)
        t_max  = max(m.timestamp for m in self.can_msgs)
        dur    = max(t_max - t_min, 0.001)

        # Frame rate
        fps = total / dur

        # Unique IDs
        id_counts: Dict[int, int] = defaultdict(int)
        for m in self.can_msgs:
            id_counts[m.msg_id] += 1

        top_ids = sorted(id_counts.items(), key=lambda x: -x[1])[:12]

        # UDS vs total
        uds_total = len(self.frames)
        uds_pct   = uds_total / total * 100 if total else 0

        # Bus load estimate (assumes 500kbps, std 8-byte frame = ~128 bits)
        avg_bits  = sum(len(m.data) * 8 + 47 for m in self.can_msgs[:1000]) / min(1000, total)
        load_pct  = min(100, fps * avg_bits / 500_000 * 100)

        # Frame count validation
        story.append(self.P(
            f"Total CAN frames parsed: {total:,}  |  "
            f"Duration: {dur:.1f}s  |  "
            f"Avg frame rate: {fps:.1f} fps  |  "
            f"Estimated bus load: {load_pct:.1f}%  |  "
            f"UDS frames: {uds_total} ({uds_pct:.2f}% of traffic)", "body_b"))
        story.append(Spacer(1, 2*mm))

        # Passive vs active detection
        all_rx = all(m.direction == "Rx" for m in self.can_msgs[:100])
        if all_rx:
            mode_msg = (
                "⚠ All frames have direction=Rx — this is a PASSIVE SNIFFER capture. "
                "Both tester and ECU frames appear as 'Rx'. "
                "The tool correctly handles this by detecting UDS patterns "
                "from data content rather than relying on direction flags."
            )
            mode_col = self.AMBER
        else:
            tx_count = sum(1 for m in self.can_msgs if m.direction == "Tx")
            mode_msg = (
                f"✓ Active capture: {tx_count} Tx frames, "
                f"{total - tx_count} Rx frames. "
                "Tester TX and ECU RX frames clearly distinguished."
            )
            mode_col = self.GREEN

        mode_tbl = Table([[Paragraph(mode_msg,
                                      ParagraphStyle("mt", fontSize=8,
                                                     fontName="Helvetica",
                                                     textColor=self.DARK,
                                                     leading=13))]],
                          colWidths=[175*mm])
        mode_tbl.setStyle(TableStyle([
            ("BACKGROUND",   (0,0),(-1,-1), colors.HexColor("#fdfaf0")),
            ("BOX",          (0,0),(-1,-1), 1.0, mode_col),
            ("TOPPADDING",   (0,0),(-1,-1), 6),
            ("BOTTOMPADDING",(0,0),(-1,-1), 6),
            ("LEFTPADDING",  (0,0),(-1,-1), 8),
        ]))
        story.append(mode_tbl)
        story.append(Spacer(1, 4*mm))

        # Top IDs table
        story.append(self.P("Top CAN IDs by frame count:", "h3"))
        id_rows = [["CAN ID", "Frame Count", "% of Total",
                    "Has UDS Traffic", "Bar"]]
        uds_id_set = set(f.src_id for f in self.frames)
        max_cnt = top_ids[0][1] if top_ids else 1
        for mid, cnt in top_ids:
            pct_str = f"{cnt/total*100:.1f}%"
            has_uds = "Yes ✓" if mid in uds_id_set else "No"
            bar_w = int(cnt / max_cnt * 40)
            bar   = "█" * bar_w + "░" * (40 - bar_w)
            uds_col = self.GREEN if mid in uds_id_set else self.DGRAY
            id_rows.append([
                Paragraph(f"0x{mid:X}",
                           ParagraphStyle("ir", fontSize=8, fontName="Courier",
                                          textColor=self.CYAN)),
                Paragraph(f"{cnt:,}",
                           ParagraphStyle("ic", fontSize=8, fontName="Courier",
                                          textColor=self.DARK, alignment=TA_RIGHT)),
                Paragraph(pct_str,
                           ParagraphStyle("ip", fontSize=8, fontName="Helvetica",
                                          textColor=self.DGRAY, alignment=TA_CENTER)),
                Paragraph(has_uds,
                           ParagraphStyle("iu", fontSize=8, fontName="Helvetica-Bold",
                                          textColor=uds_col, alignment=TA_CENTER)),
                Paragraph(bar[:30],
                           ParagraphStyle("ib", fontSize=6, fontName="Courier",
                                          textColor=self.TEAL)),
            ])
        col_w = [26*mm, 26*mm, 22*mm, 28*mm, 70*mm]
        tbl = Table(id_rows, colWidths=col_w)
        tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0), self.DARK),
            ("TEXTCOLOR",     (0,0), (-1,0), self.WHITE),
            ("FONT",          (0,0), (-1,0), "Helvetica-Bold", 8),
            ("ROWBACKGROUNDS",(0,1),(-1,-1), [self.WHITE, self.LGRAY]),
            ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
            ("TOPPADDING",    (0,0), (-1,-1), 4),
            ("BOTTOMPADDING", (0,0), (-1,-1), 4),
            ("BOX",           (0,0), (-1,-1), 0.5, self.MGRAY),
            ("INNERGRID",     (0,0), (-1,-1), 0.3, self.MGRAY),
        ]))
        story.append(tbl)

        # Frame count validation note
        story.append(Spacer(1, 4*mm))
        validation_text = (
            f"Frame Count Validation: {total:,} CAN frames parsed by tool.  "
            f"If this differs from your log viewer's count, check: "
            f"(1) Filter settings in log viewer, "
            f"(2) Log viewer may count error frames separately, "
            f"(3) BusMaster timestamps with 4-digit sub-seconds "
            f"(e.g. 15:44:23:5159) are correctly parsed using /10000 divisor."
        )
        story.append(Paragraph(validation_text,
                                ParagraphStyle("vn", fontSize=8, fontName="Helvetica",
                                               textColor=self.DGRAY, leading=13,
                                               spaceAfter=4)))
        return story
    def _appendix(self) -> list:
        story = [PageBreak(), self.P("Appendix A — UDS Service Reference", "h1"),
                 HRFlowable(width="100%", thickness=1, color=self.TEAL), Spacer(1, 2*mm)]
        rows = [["SID", "Service Name", "Flash Relevance"]]
        flash_rel = {
            0x10: "Required — enter programming session",
            0x27: "Required — unlock security",
            0x28: "Recommended — disable Rx/Tx",
            0x31: "Required — erase / check",
            0x34: "Required — request download",
            0x36: "Required — transfer data blocks",
            0x37: "Required — end transfer",
            0x3E: "Required — keep-alive",
            0x85: "Recommended — disable DTCs",
            0x11: "Required — ECU reset after flash",
        }
        for sid, name in UDS_SERVICES.items():
            rows.append([
                f"0x{sid:02X}", name,
                flash_rel.get(sid, "Optional / diagnostic"),
            ])
        tbl = Table(rows, colWidths=[18*mm, 70*mm, 92*mm])
        tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0,0),(-1,0), self.DARK),
            ("TEXTCOLOR",     (0,0),(-1,0), self.WHITE),
            ("FONT",          (0,0),(-1,0), "Helvetica-Bold", 8),
            ("FONT",          (0,1),(-1,-1),"Helvetica", 8),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[self.WHITE, self.LGRAY]),
            ("ALIGN",         (0,0),(0,-1), "CENTER"),
            ("VALIGN",        (0,0),(-1,-1),"MIDDLE"),
            ("TOPPADDING",    (0,0),(-1,-1), 4),
            ("BOTTOMPADDING", (0,0),(-1,-1), 4),
            ("BOX",           (0,0),(-1,-1), 0.5, self.MGRAY),
            ("INNERGRID",     (0,0),(-1,-1), 0.3, self.MGRAY),
        ]))
        story.append(tbl)

        story += [Spacer(1,6*mm), self.P("Appendix B — NRC Code Reference", "h1"),
                  HRFlowable(width="100%", thickness=1, color=self.TEAL), Spacer(1,2*mm)]
        nrc_rows = [["NRC", "Name", "Severity", "Common Cause"]]
        nrc_sev = {
            0x22:"ERROR",0x24:"ERROR",0x31:"WARNING",0x33:"CRITICAL",
            0x35:"CRITICAL",0x36:"CRITICAL",0x70:"ERROR",0x71:"WARNING",
            0x72:"CRITICAL",0x73:"CRITICAL",0x78:"INFO",0x7E:"ERROR",0x7F:"ERROR",
        }
        nrc_cause = {
            0x22:"Pre-condition not met (session/voltage/speed)",
            0x24:"Wrong service sequence order",
            0x31:"Address or parameter out of range",
            0x33:"Security not unlocked before service",
            0x35:"Wrong seed-key algorithm or byte order",
            0x36:"Too many failed security attempts — lockout",
            0x70:"Download not accepted — erase not done",
            0x71:"Transfer suspended — reduce block size",
            0x72:"Flash write/erase hardware failure",
            0x73:"Block sequence counter mismatch",
            0x78:"ECU processing — normal, increase P2* timeout",
            0x7E:"Sub-function not allowed in this session",
            0x7F:"Service not allowed in this session",
        }
        for code, name in UDS_NRC.items():
            sev = nrc_sev.get(code, "INFO")
            sev_col = self.SEV_COLORS.get(sev, self.BLUE)
            nrc_rows.append([
                Paragraph(f"0x{code:02X}",
                           ParagraphStyle("nc", fontSize=8, fontName="Courier",
                                          textColor=self.DGRAY, alignment=TA_CENTER)),
                name,
                Paragraph(sev, ParagraphStyle("ns", fontSize=8, fontName="Helvetica-Bold",
                                               textColor=self.WHITE, backColor=sev_col,
                                               alignment=TA_CENTER)),
                nrc_cause.get(code, "See ECU specification"),
            ])
        nrc_tbl = Table(nrc_rows, colWidths=[16*mm, 60*mm, 22*mm, 82*mm])
        nrc_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0,0),(-1,0), self.DARK),
            ("TEXTCOLOR",     (0,0),(-1,0), self.WHITE),
            ("FONT",          (0,0),(-1,0), "Helvetica-Bold", 8),
            ("FONT",          (0,1),(-1,-1),"Helvetica", 8),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[self.WHITE, self.LGRAY]),
            ("ALIGN",         (0,0),(0,-1),"CENTER"),
            ("VALIGN",        (0,0),(-1,-1),"MIDDLE"),
            ("TOPPADDING",    (0,0),(-1,-1), 4),
            ("BOTTOMPADDING", (0,0),(-1,-1), 4),
            ("BOX",           (0,0),(-1,-1), 0.5, self.MGRAY),
            ("INNERGRID",     (0,0),(-1,-1), 0.3, self.MGRAY),
        ]))
        story.append(nrc_tbl)
        return story

    # ── page decoration ───────────────────────────────────────────────────────
    @staticmethod
    def _page_header_footer(canvas_obj, doc):
        canvas_obj.saveState()
        W, H = A4
        # Header bar
        canvas_obj.setFillColor(colors.HexColor("#1a1a2e"))
        canvas_obj.rect(0, H-8*mm, W, 8*mm, stroke=0, fill=1)
        canvas_obj.setFont("Helvetica-Bold", 8)
        canvas_obj.setFillColor(colors.white)
        canvas_obj.drawString(15*mm, H-5.5*mm, "CANvas UDS Flash Analyzer")
        canvas_obj.setFont("Helvetica", 8)
        canvas_obj.drawRightString(W-15*mm, H-5.5*mm, "UDS Flash RCA Report — CONFIDENTIAL")
        # Footer
        canvas_obj.setFillColor(colors.HexColor("#f4f4f4"))
        canvas_obj.rect(0, 0, W, 8*mm, stroke=0, fill=1)
        canvas_obj.setFillColor(colors.HexColor("#888888"))
        canvas_obj.setFont("Helvetica", 7)
        canvas_obj.drawString(15*mm, 3*mm,
                               f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        canvas_obj.drawCentredString(W/2, 3*mm, "ISO 14229-1 / ISO 15765-2")
        canvas_obj.drawRightString(W-15*mm, 3*mm, f"Page {doc.page}")
        canvas_obj.restoreState()


# ═══════════════════════════════════════════════════════════════════════════════
# ANALYSIS WORKER THREAD
# ═══════════════════════════════════════════════════════════════════════════════
class AnalysisWorker(QThread):
    progress  = pyqtSignal(int, str)
    finished  = pyqtSignal(list, list, list, list, str, list)   # issues, seqs, uds_frames, can_msgs, log_path, resp_times
    error     = pyqtSignal(str)

    def __init__(self, log_path: str):
        super().__init__()
        self.log_path = log_path

    def run(self):
        try:
            self.progress.emit(5, "Parsing CAN log…")
            can_msgs, warns = CANLogParser.parse(self.log_path)
            if not can_msgs:
                self.error.emit(
                    "No CAN frames found in log.\n\n"
                    "Supported formats:\n"
                    "  • BusMaster .log  (BusMaster 3.x — primary)\n"
                    "  • Vector ASC .asc\n"
                    "  • PCAN Viewer .trc\n"
                    "  • CSV / plain text\n\n"
                    "Check file is not empty and matches one of these formats.")
                return

            unique_ids = sorted(set(m.msg_id for m in can_msgs))
            self.progress.emit(20,
                f"Parsed {len(can_msgs):,} CAN frames, "
                f"{len(unique_ids)} unique IDs. Detecting UDS pairs…")

            # ── Detect ECU pairs ──────────────────────────────────────────────
            pairs = detect_uds_pairs(can_msgs)
            pair_str = ", ".join(f"0x{t:X}↔0x{r:X}" for t, r in pairs[:5])
            self.progress.emit(35, f"Pairs: {pair_str}. Reassembling ISO-TP…")

            # ── Reassemble ISO-TP and decode UDS frames ───────────────────────
            # Key fix: use a GLOBAL dedup set keyed on (timestamp, payload_hash)
            # so even if the same pair appears twice in `pairs` (forward/reverse),
            # we never count the same physical frame twice.
            uds_frames   : List[UDSFrame] = []
            seen_payloads: set            = set()

            for tx_id, rx_id in pairs:
                reassembler = ISOTPReassembler(rx_id=rx_id, tx_id=tx_id)
                if tx_id == rx_id:
                    for msg in can_msgs:
                        if msg.msg_id == tx_id:
                            reassembler.feed(msg)
                else:
                    for msg in can_msgs:
                        if msg.msg_id in (tx_id, rx_id):
                            reassembler.feed(msg)

                for ts, payload, is_resp, first_can in reassembler.complete_frames:
                    # ── Dedup: (timestamp rounded to 0.1ms, full payload) ─────
                    dedup_key = (round(ts, 4), bytes(payload))
                    if dedup_key in seen_payloads:
                        continue
                    seen_payloads.add(dedup_key)

                    # ── Validate: ONLY accept genuine UDS service IDs ──────────
                    # Reject payloads whose first byte is not a valid UDS SID
                    # after ISO-TP header stripping.
                    if not payload:
                        continue
                    sid = payload[0]
                    # NRC: first byte 0x7F, second byte = failing SID, third = NRC
                    if sid == 0x7F:
                        if len(payload) < 3:
                            continue            # malformed NRC
                        failing_sid = payload[1] & 0xBF
                        if failing_sid not in UDS_ALL_SIDS:
                            continue            # NRC for unknown service → skip
                    else:
                        actual_sid = sid & 0xBF   # strip response bit
                        if actual_sid not in UDS_ALL_SIDS:
                            continue            # not a UDS service → skip

                    src = rx_id if is_resp else tx_id
                    dst = tx_id if is_resp else rx_id
                    f   = decode_uds_frames(payload, ts, src, dst, is_resp, first_can)
                    if f:
                        uds_frames.append(f)

            uds_frames.sort(key=lambda f: f.timestamp)
            self.progress.emit(65,
                f"Decoded {len(uds_frames)} UDS frames. Running flash analysis…")

            analyzer = UDSFlashAnalyzer(uds_frames, can_msgs)
            self.progress.emit(95, "Analysis complete.")

            self.finished.emit(analyzer.issues, analyzer.sequences,
                               uds_frames, can_msgs, self.log_path,
                               analyzer.resp_times)
        except Exception as ex:
            import traceback
            self.error.emit(f"Analysis error: {ex}\n\n{traceback.format_exc()}")


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN GUI WINDOW
# ═══════════════════════════════════════════════════════════════════════════════
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("UDS Flash Log Analyzer — RCA Report Generator")
        self.resize(1380, 860)
        self.setStyleSheet(SS)
        self.setAcceptDrops(True)

        self._issues:    List[Issue]       = []
        self._sequences: List[FlashSequence] = []
        self._uds_frames: List[UDSFrame]   = []
        self._can_msgs:  List[CANMsg]      = []
        self._resp_times: List[Dict]       = []
        self._log_path   = ""
        self._worker: Optional[AnalysisWorker] = None

        self._build_ui()

    # ── layout ────────────────────────────────────────────────────────────────
    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_lyt = QVBoxLayout(central)
        main_lyt.setContentsMargins(0, 0, 0, 0)
        main_lyt.setSpacing(0)

        # ── TOP BAR ──────────────────────────────────────────────────────────
        topbar = QWidget()
        topbar.setStyleSheet(f"background:{C['bg2']};border-bottom:1px solid {C['border']};")
        topbar.setFixedHeight(56)
        tbl = QHBoxLayout(topbar)
        tbl.setContentsMargins(14, 8, 14, 8)
        tbl.setSpacing(10)

        logo = QLabel("🔍  UDS Flash Analyzer")
        logo.setStyleSheet(f"color:{C['cyan']};font-size:16px;font-weight:bold;")
        tbl.addWidget(logo)
        tbl.addStretch()

        self._file_lbl = QLabel("No file loaded — drop a CAN log here or click Browse")
        self._file_lbl.setStyleSheet(f"color:{C['text3']};font-size:10px;")
        tbl.addWidget(self._file_lbl)

        browse_btn = QPushButton("📂  Browse Log")
        browse_btn.setObjectName("btn_primary")
        browse_btn.clicked.connect(self._browse_file)
        tbl.addWidget(browse_btn)

        self._analyze_btn = QPushButton("▶  Analyze")
        self._analyze_btn.setObjectName("btn_green")
        self._analyze_btn.setEnabled(False)
        self._analyze_btn.clicked.connect(self._start_analysis)
        tbl.addWidget(self._analyze_btn)

        self._pdf_btn = QPushButton("📄  Export PDF Report")
        self._pdf_btn.setObjectName("btn_primary")
        self._pdf_btn.setEnabled(False)
        self._pdf_btn.clicked.connect(self._export_pdf)
        tbl.addWidget(self._pdf_btn)

        main_lyt.addWidget(topbar)

        # ── PROGRESS BAR ─────────────────────────────────────────────────────
        self._progress = QProgressBar()
        self._progress.setRange(0, 100)
        self._progress.setValue(0)
        self._progress.setFixedHeight(4)
        self._progress.setStyleSheet(f"""
            QProgressBar{{background:{C['bg3']};border:none;}}
            QProgressBar::chunk{{background:{C['cyan']};}}
        """)
        main_lyt.addWidget(self._progress)

        # ── MAIN CONTENT ─────────────────────────────────────────────────────
        self._tabs = QTabWidget()
        self._tabs.setDocumentMode(True)
        main_lyt.addWidget(self._tabs, 1)

        self._tabs.addTab(self._build_drop_tab(),    "Home")
        self._tabs.addTab(self._build_issues_tab(),  "Issues")
        self._tabs.addTab(self._build_timeline_tab(),"UDS Timeline")
        self._tabs.addTab(self._build_raw_tab(),     "Raw Log")
        self._tabs.addTab(self._build_stats_tab(),   "Statistics")

        # ── STATUS BAR ───────────────────────────────────────────────────────
        sb = self.statusBar()
        self._sb_frames = QLabel("Frames: —")
        self._sb_uds    = QLabel("UDS: —")
        self._sb_issues = QLabel("Issues: —")
        self._sb_status = QLabel("Ready")
        for w in [self._sb_frames, self._sb_uds, self._sb_issues, self._sb_status]:
            sb.addWidget(w)
            sb.addPermanentWidget(QLabel("  |  "))

    # ── HOME / DROP TAB ──────────────────────────────────────────────────────
    def _build_drop_tab(self) -> QWidget:
        w = QWidget()
        lyt = QVBoxLayout(w)
        lyt.setAlignment(Qt.AlignmentFlag.AlignCenter)

        drop_frame = QFrame()
        drop_frame.setFixedSize(600, 320)
        drop_frame.setStyleSheet(f"""
            QFrame{{background:{C['bg2']};border:2px dashed {C['border']};
                   border-radius:12px;}}
            QFrame:hover{{border-color:{C['cyan']};}}
        """)
        df_lyt = QVBoxLayout(drop_frame)
        df_lyt.setAlignment(Qt.AlignmentFlag.AlignCenter)

        icon_lbl = QLabel("📋")
        icon_lbl.setStyleSheet("font-size:64px;")
        icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        df_lyt.addWidget(icon_lbl)

        t1 = QLabel("Drop CAN Log File Here")
        t1.setStyleSheet(f"color:{C['text']};font-size:18px;font-weight:bold;")
        t1.setAlignment(Qt.AlignmentFlag.AlignCenter)
        df_lyt.addWidget(t1)

        t2 = QLabel("Supports: Vector ASC  ·  BusMaster LOG  ·  PCAN TRC  ·  CSV / Text")
        t2.setStyleSheet(f"color:{C['text3']};font-size:11px;")
        t2.setAlignment(Qt.AlignmentFlag.AlignCenter)
        df_lyt.addWidget(t2)

        df_lyt.addSpacing(16)

        browse2 = QPushButton("📂  Browse for Log File")
        browse2.setObjectName("btn_primary")
        browse2.setFixedWidth(200)
        browse2.clicked.connect(self._browse_file)
        df_lyt.addWidget(browse2, alignment=Qt.AlignmentFlag.AlignCenter)

        lyt.addWidget(drop_frame, alignment=Qt.AlignmentFlag.AlignCenter)

        # Features list
        feat_grp = QGroupBox("Detected Issues Include")
        feat_grp.setFixedWidth(600)
        feat_lyt = QGridLayout(feat_grp)
        features = [
            "Session control failures",     "Security access denied / wrong key",
            "Memory erase failures",        "Download request rejections",
            "TransferData block errors",    "Block sequence counter faults",
            "ISO-TP timing violations",     "TesterPresent gaps / missing",
            "NRC code analysis (all codes)","P2* timer expiry detection",
            "Wrong session errors",         "Post-flash integrity check missing",
            "Communication control",        "DTC management issues",
        ]
        for i, f in enumerate(features):
            feat_lyt.addWidget(QLabel(f"✓  {f}"), i//2, i%2)
        lyt.addWidget(feat_grp, alignment=Qt.AlignmentFlag.AlignCenter)
        return w

    # ── ISSUES TAB ────────────────────────────────────────────────────────────
    def _build_issues_tab(self) -> QWidget:
        w = QWidget()
        lyt = QVBoxLayout(w)
        lyt.setContentsMargins(0, 0, 0, 0)
        lyt.setSpacing(0)

        # Filter bar
        fbar = QWidget()
        fbar.setStyleSheet(f"background:{C['bg2']};border-bottom:1px solid {C['border']};")
        fb = QHBoxLayout(fbar)
        fb.setContentsMargins(8, 4, 8, 4)
        fb.addWidget(QLabel("Filter:"))
        self._issue_filter = QLineEdit()
        self._issue_filter.setPlaceholderText("Search issues…")
        self._issue_filter.setFixedWidth(200)
        self._issue_filter.textChanged.connect(self._filter_issues)
        fb.addWidget(self._issue_filter)

        fb.addWidget(QLabel("Severity:"))
        self._sev_filter = QComboBox()
        self._sev_filter.addItems(["All", "CRITICAL", "ERROR", "WARNING", "INFO"])
        self._sev_filter.currentTextChanged.connect(self._filter_issues)
        fb.addWidget(self._sev_filter)
        fb.addStretch()

        # Severity counts
        self._sev_labels = {}
        for sev, col in SEVERITY_COLORS.items():
            lbl = QLabel(f"  {sev}: 0  ")
            lbl.setStyleSheet(f"background:{col};color:#fff;border-radius:3px;font-size:10px;font-weight:bold;padding:2px 6px;")
            fb.addWidget(lbl)
            self._sev_labels[sev] = lbl
        lyt.addWidget(fbar)

        # Splitter: table left, detail right
        sp = QSplitter(Qt.Orientation.Horizontal)

        self._issue_table = QTableWidget()
        self._issue_table.setColumnCount(5)
        self._issue_table.setHorizontalHeaderLabels(
            ["Severity", "Code", "Service", "Title", "Timestamp"])
        hh = self._issue_table.horizontalHeader()
        hh.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self._issue_table.verticalHeader().setVisible(False)
        self._issue_table.setAlternatingRowColors(True)
        self._issue_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._issue_table.setSortingEnabled(False)
        self._issue_table.setShowGrid(False)
        for i, w2 in enumerate([75, 70, 110, 300, 75]):
            self._issue_table.setColumnWidth(i, w2)
        self._issue_table.currentCellChanged.connect(self._issue_selected)
        sp.addWidget(self._issue_table)

        # Detail panel
        detail_w = QWidget()
        detail_w.setStyleSheet(f"background:{C['bg2']};")
        dv = QVBoxLayout(detail_w)
        dv.setContentsMargins(12, 12, 12, 12)
        dv.setSpacing(8)

        self._detail_title = QLabel("Select an issue to see details")
        self._detail_title.setStyleSheet(f"color:{C['cyan']};font-size:13px;font-weight:bold;")
        self._detail_title.setWordWrap(True)
        dv.addWidget(self._detail_title)

        sep = QFrame(); sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet(f"color:{C['border']};"); dv.addWidget(sep)

        self._detail_text = QTextEdit()
        self._detail_text.setReadOnly(True)
        dv.addWidget(self._detail_text, 1)
        detail_w.setMinimumWidth(380)
        sp.addWidget(detail_w)
        sp.setSizes([580, 420])
        lyt.addWidget(sp, 1)
        return w

    # ── TIMELINE TAB ─────────────────────────────────────────────────────────
    def _build_timeline_tab(self) -> QWidget:
        w = QWidget()
        lyt = QVBoxLayout(w)
        lyt.setContentsMargins(0, 0, 0, 0)

        fbar = QWidget()
        fbar.setStyleSheet(f"background:{C['bg2']};border-bottom:1px solid {C['border']};")
        fb = QHBoxLayout(fbar)
        fb.setContentsMargins(8, 4, 8, 4)
        fb.addWidget(QLabel("Filter:"))
        self._tl_filter = QLineEdit()
        self._tl_filter.setPlaceholderText("Service name or hex…")
        self._tl_filter.setFixedWidth(200)
        self._tl_filter.textChanged.connect(self._filter_timeline)
        fb.addWidget(self._tl_filter)
        self._tl_nrc_only = QCheckBox("NRC only")
        self._tl_nrc_only.stateChanged.connect(self._filter_timeline)
        fb.addWidget(self._tl_nrc_only)
        fb.addStretch()
        lyt.addWidget(fbar)

        self._tl_table = QTableWidget()
        self._tl_table.setColumnCount(8)
        self._tl_table.setHorizontalHeaderLabels(
            ["Time (s)", "Dir", "Src ID", "Service", "Sub-Func", "NRC", "Data (Hex)", "Line"])
        hh = self._tl_table.horizontalHeader()
        hh.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        self._tl_table.verticalHeader().setVisible(False)
        self._tl_table.setAlternatingRowColors(True)
        self._tl_table.setShowGrid(False)
        for i, w2 in enumerate([70, 36, 55, 160, 60, 130, 200, 50]):
            self._tl_table.setColumnWidth(i, w2)
        lyt.addWidget(self._tl_table, 1)
        return w

    # ── RAW LOG TAB ───────────────────────────────────────────────────────────
    def _build_raw_tab(self) -> QWidget:
        w = QWidget()
        lyt = QVBoxLayout(w)
        lyt.setContentsMargins(0, 0, 0, 0)
        fbar = QWidget()
        fbar.setStyleSheet(f"background:{C['bg2']};border-bottom:1px solid {C['border']};")
        fb = QHBoxLayout(fbar)
        fb.setContentsMargins(8, 4, 8, 4)
        fb.addWidget(QLabel("Filter:"))
        self._raw_filter = QLineEdit()
        self._raw_filter.setPlaceholderText("ID or hex data…")
        self._raw_filter.setFixedWidth(200)
        self._raw_filter.textChanged.connect(self._filter_raw)
        fb.addWidget(self._raw_filter)
        fb.addStretch()
        lyt.addWidget(fbar)

        self._raw_table = QTableWidget()
        self._raw_table.setColumnCount(6)
        self._raw_table.setHorizontalHeaderLabels(
            ["Time (s)", "Ch", "ID", "DLC", "Data (Hex)", "Line"])
        self._raw_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self._raw_table.verticalHeader().setVisible(False)
        self._raw_table.setAlternatingRowColors(True)
        self._raw_table.setShowGrid(False)
        for i, w2 in enumerate([70, 30, 70, 36, 280, 50]):
            self._raw_table.setColumnWidth(i, w2)
        lyt.addWidget(self._raw_table, 1)
        return w

    # ── STATS TAB ─────────────────────────────────────────────────────────────
    def _build_stats_tab(self) -> QWidget:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        inner = QWidget()
        lyt = QVBoxLayout(inner)
        lyt.setContentsMargins(16, 16, 16, 16)
        lyt.setSpacing(12)

        self._stats_text = QTextEdit()
        self._stats_text.setReadOnly(True)
        self._stats_text.setStyleSheet(f"background:{C['bg2']};color:{C['text']};border:none;")
        lyt.addWidget(self._stats_text)
        scroll.setWidget(inner)
        return scroll

    # ── ANALYSIS LOGIC ────────────────────────────────────────────────────────
    def _browse_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Open CAN Log File", "",
            "CAN Log Files (*.asc *.log *.trc *.csv *.txt);;All Files (*)")
        if path:
            self._set_log(path)

    def _set_log(self, path: str):
        self._log_path = path
        self._file_lbl.setText(f"📋  {os.path.basename(path)}  ({os.path.getsize(path)//1024} KB)")
        self._analyze_btn.setEnabled(True)
        self._sb_status.setText(f"Loaded: {os.path.basename(path)}")

    def _start_analysis(self):
        if not self._log_path:
            return
        self._analyze_btn.setEnabled(False)
        self._pdf_btn.setEnabled(False)
        self._progress.setValue(0)
        self._sb_status.setText("Analyzing…")

        self._worker = AnalysisWorker(self._log_path)
        self._worker.progress.connect(self._on_progress)
        self._worker.finished.connect(self._on_finished)
        self._worker.error.connect(self._on_error)
        self._worker.start()

    def _on_progress(self, pct: int, msg: str):
        self._progress.setValue(pct)
        self._sb_status.setText(msg)

    def _on_finished(self, issues, seqs, uds_frames, can_msgs, log_path, resp_times):
        self._issues      = issues
        self._sequences   = seqs
        self._uds_frames  = uds_frames
        self._can_msgs    = can_msgs
        self._log_path    = log_path
        self._resp_times  = resp_times
        self._progress.setValue(100)
        self._populate_all()
        self._analyze_btn.setEnabled(True)
        self._pdf_btn.setEnabled(True)
        c = sum(1 for i in issues if i.severity == "CRITICAL")
        e = sum(1 for i in issues if i.severity == "ERROR")

        unique_ids = sorted(set(m.msg_id for m in can_msgs))
        self._sb_frames.setText(f"Frames: {len(can_msgs):,}")
        self._sb_uds.setText(f"UDS: {len(uds_frames)}")
        self._sb_issues.setText(f"Issues: {len(issues)} ({c} CRIT, {e} ERR)")

        if len(uds_frames) == 0:
            id_list = ", ".join(f"0x{i:X}" for i in unique_ids[:15])
            self._sb_status.setText(
                f"No UDS found — CAN IDs: {id_list}")
            # Show diagnostics popup
            QMessageBox.information(
                self, "Analysis Complete — No UDS Frames Found",
                f"Parsed {len(can_msgs):,} CAN frames from log.\n\n"
                f"Unique CAN IDs in log ({len(unique_ids)} total):\n"
                f"  {id_list}\n\n"
                f"No ISO-TP/UDS frames were decoded.\n\n"
                f"Possible reasons:\n"
                f"  1. This log does not contain UDS/diagnostic traffic\n"
                f"  2. Log format was not parsed correctly — check Raw Log tab\n"
                f"  3. UDS traffic uses non-standard byte framing\n\n"
                f"Check the Raw Log tab to verify CAN IDs and data are correct.\n"
                f"If IDs are wrong (all showing same value), the log format\n"
                f"may not match BusMaster/ASC/TRC standard — try renaming\n"
                f"to .asc or .csv and re-loading."
            )
            self._tabs.setCurrentIndex(3)   # Raw Log tab
        else:
            # Build per-sequence outcome summary for status bar
            any_exit = any(s.transfer_exit_ok   for s in seqs)
            any_prog = any(s.programming_session for s in seqs)
            any_sa   = any(s.security_access_ok  for s in seqs)
            any_dl   = any(s.download_requested or s.transfer_frames > 0
                           for s in seqs)
            if not seqs:
                ui_verdict = "NO FLASH SEQUENCE DETECTED"
            elif any_exit:
                all_passed = all(s.transfer_exit_ok for s in seqs)
                if all_passed and c == 0 and e == 0:
                    ui_verdict = f"ALL {len(seqs)} SEQUENCE(S) PASSED"
                elif all_passed:
                    ui_verdict = f"ALL {len(seqs)} SEQUENCE(S) PASSED WITH WARNINGS"
                else:
                    n_pass = sum(1 for s in seqs if s.transfer_exit_ok)
                    n_fail = len(seqs) - n_pass
                    ui_verdict = f"{n_pass} PASSED / {n_fail} FAILED"
            elif any_dl:
                ui_verdict = "FLASH INCOMPLETE — TRANSFER NOT FINISHED"
            elif any_sa:
                ui_verdict = "FLASH FAILED — DOWNLOAD NOT STARTED"
            elif any_prog:
                ui_verdict = "FLASH FAILED — SECURITY ACCESS FAILED"
            else:
                ui_verdict = "FLASH FAILED — SESSION NOT ESTABLISHED"

            # Per-sequence detail for status
            seq_detail = "  |  ".join(
                f"Seq{i}: {'✓ PASS' if s.transfer_exit_ok else '✗ FAIL'} "
                f"({s.transfer_frames} blks)"
                for i, s in enumerate(seqs, 1)
            )
            self._sb_status.setText(
                f"{ui_verdict}  ▸  {seq_detail}  |  {len(uds_frames)} UDS  |  {len(issues)} issues")
            self._tabs.setCurrentIndex(1)   # Issues tab

    def _on_error(self, msg: str):
        self._analyze_btn.setEnabled(True)
        self._sb_status.setText("Error")
        QMessageBox.critical(self, "Analysis Error", msg)

    # ── POPULATE UI ──────────────────────────────────────────────────────────
    def _populate_all(self):
        self._populate_issues()
        self._populate_timeline()
        self._populate_raw()
        self._populate_stats()

    def _populate_issues(self):
        self._issue_table.setRowCount(0)
        for issue in self._issues:
            self._add_issue_row(issue)
        for sev, lbl in self._sev_labels.items():
            cnt = sum(1 for i in self._issues if i.severity == sev)
            lbl.setText(f"  {sev}: {cnt}  ")

    def _add_issue_row(self, issue: Issue):
        col = SEVERITY_COLORS.get(issue.severity, C["text2"])
        tbl = self._issue_table
        r = tbl.rowCount(); tbl.insertRow(r); tbl.setRowHeight(r, 24)

        sev_item = QTableWidgetItem(issue.severity)
        sev_item.setForeground(QBrush(QColor("#ffffff")))
        sev_item.setBackground(QBrush(QColor(col)))
        sev_item.setFont(QFont("Consolas", 9, QFont.Weight.Bold))
        sev_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        sev_item.setData(Qt.ItemDataRole.UserRole, id(issue))

        code_item = QTableWidgetItem(issue.code)
        code_item.setForeground(QBrush(QColor(C["amber"])))

        srv_item  = QTableWidgetItem(issue.service[:22])
        srv_item.setForeground(QBrush(QColor(C["text2"])))

        title_item = QTableWidgetItem(issue.title)
        title_item.setForeground(QBrush(QColor(C["text"])))

        ts_item = QTableWidgetItem(
            f"{issue.timestamp:.3f}s" if issue.timestamp else "—")
        ts_item.setForeground(QBrush(QColor(C["text3"])))
        ts_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

        for c, item in enumerate([sev_item,code_item,srv_item,title_item,ts_item]):
            tbl.setItem(r, c, item)

    def _issue_selected(self, row, _col, _pr, _pc):
        if row < 0 or row >= self._issue_table.rowCount():
            return
        issue_id = self._issue_table.item(row, 0)
        if issue_id is None:
            return
        uid = issue_id.data(Qt.ItemDataRole.UserRole)
        issue = next((i for i in self._issues if id(i) == uid), None)
        if not issue:
            return
        self._detail_title.setText(f"[{issue.code}] {issue.title}")
        col = SEVERITY_COLORS.get(issue.severity, C["text2"])
        html = f"""
        <style>
            body {{color:{C['text']};font-family:Consolas,monospace;font-size:11px;}}
            .section {{color:{C['cyan']};font-weight:bold;font-size:12px;margin-top:12px;}}
            .label {{color:{C['text3']};font-size:10px;}}
            .value {{color:{C['amber']};font-family:Courier;}}
            .body  {{color:{C['text']};line-height:1.6;}}
            .bullet {{margin-left:12px;}}
        </style>
        <div class="label">SEVERITY</div>
        <div style="background:{col};color:#fff;padding:3px 8px;border-radius:3px;
                    display:inline-block;font-weight:bold;">{issue.severity}</div>
        <br><div class="label">SERVICE</div>
        <div class="value">{issue.service}</div>
        <div class="label">TIMESTAMP</div>
        <div class="value">{f'{issue.timestamp:.3f}s' if issue.timestamp else '—'}</div>
        <div class="label">RAW DATA</div>
        <div class="value" style="background:{C['bg3']};padding:4px 8px;">{issue.raw_data}</div>
        <div class="section">📋 Description</div>
        <div class="body">{issue.description}</div>
        <div class="section">🔍 Root Cause Analysis</div>
        <div class="body">{issue.root_cause.replace(chr(10),'<br>')}</div>
        <div class="section">🔧 Corrective Action</div>
        <div class="body">{issue.corrective_action.replace(chr(10),'<br>')}</div>
        <div class="section">🛡 Preventive Action</div>
        <div class="body">{issue.preventive_action.replace(chr(10),'<br>')}</div>
        """
        self._detail_text.setHtml(html)

    def _populate_timeline(self):
        self._tl_table.setRowCount(0)
        for f in self._uds_frames:
            self._add_tl_row(f)

    def _add_tl_row(self, f: UDSFrame):
        tbl = self._tl_table
        r = tbl.rowCount(); tbl.insertRow(r); tbl.setRowHeight(r, 22)
        nrc_str = UDS_NRC.get(f.nrc_code, f"0x{f.nrc_code:02X}") if f.is_nrc else ""
        cells = [
            (f"{f.timestamp:.3f}",               C["text3"]),
            (f.direction_str,                     C["green"] if not f.is_response else C["accent"]),
            (f"0x{f.src_id:03X}",                C["cyan"]),
            (f"0x{f.service_id:02X} {f.service_name[:16]}", C["text"]),
            (f"0x{f.sub_func:02X}" if f.sub_func is not None else "—", C["text2"]),
            (nrc_str[:18],                        C["red"] if f.is_nrc else C["text3"]),
            (f.data.hex().upper()[:36],           C["amber"]),
            (str(f.line_no),                      C["text3"]),
        ]
        for c, (val, col) in enumerate(cells):
            it = QTableWidgetItem(val)
            it.setForeground(QBrush(QColor(col)))
            tbl.setItem(r, c, it)
        if f.is_nrc and f.nrc_code != 0x78:
            for c in range(tbl.columnCount()):
                item = tbl.item(r, c)
                if item:
                    item.setBackground(QBrush(QColor("#2d1a1a")))

    def _populate_raw(self):
        self._raw_table.setRowCount(0)
        for msg in self._can_msgs[:2000]:  # first 2000
            r = self._raw_table.rowCount()
            self._raw_table.insertRow(r)
            self._raw_table.setRowHeight(r, 20)
            cells = [
                (f"{msg.timestamp:.3f}",  C["text3"]),
                (str(msg.channel),        C["text2"]),
                (msg.id_str,              C["cyan"]),
                (str(len(msg.data)),      C["text2"]),
                (msg.data_hex,            C["amber"]),
                (str(msg.line_no),        C["text3"]),
            ]
            for c, (val, col) in enumerate(cells):
                it = QTableWidgetItem(val)
                it.setForeground(QBrush(QColor(col)))
                self._raw_table.setItem(r, c, it)

    def _populate_stats(self):
        c = sum(1 for i in self._issues if i.severity == "CRITICAL")
        e = sum(1 for i in self._issues if i.severity == "ERROR")
        w = sum(1 for i in self._issues if i.severity == "WARNING")
        info = sum(1 for i in self._issues if i.severity == "INFO")
        prog = sum(1 for s in self._sequences if s.programming_session)
        sa   = sum(1 for s in self._sequences if s.security_access_ok)
        done = sum(1 for s in self._sequences if s.transfer_exit_ok)
        svc_counts: Dict[str, int] = defaultdict(int)
        for f in self._uds_frames:
            svc_counts[f.service_name] += 1

        # Build per-sequence verdict rows
        seq_rows_html = ""
        for i, s in enumerate(self._sequences, 1):
            if s.transfer_exit_ok and s.security_access_ok:
                out = f'<span style="color:{C["green"]}">✓ COMPLETED</span>'
                if not s.check_ok:
                    out += f' <span style="color:{C["amber"]}">(no integrity check)</span>'
            elif s.download_requested or s.transfer_frames > 0:
                out = f'<span style="color:{C["orange"]}">✗ INCOMPLETE</span>'
            elif s.security_access_ok:
                out = f'<span style="color:{C["red"]}">✗ DOWNLOAD NOT STARTED</span>'
            elif s.programming_session:
                out = f'<span style="color:{C["red"]}">✗ SECURITY ACCESS FAILED</span>'
            else:
                out = f'<span style="color:{C["red"]}">✗ SESSION NOT ESTABLISHED</span>'
            dur = f"{s.duration:.1f}s" if s.duration else "—"
            ecu = f"0x{s.ecu_address:X}" if s.ecu_address else "—"
            seq_rows_html += (
                f'<tr><td><b>Seq {i}</b></td><td>{out}</td>' +
                f'<td>{s.transfer_frames} blocks</td><td>{dur}</td><td>{ecu}</td></tr>'
            )

        html = f"""
        <style>
            body{{color:{C['text']};font-family:Consolas,monospace;font-size:11px;}}
            h2{{color:{C['cyan']};margin-top:14px;}}
            table{{border-collapse:collapse;width:100%;margin-bottom:16px;}}
            th{{background:{C['bg3']};color:{C['text2']};padding:5px 10px;text-align:left;}}
            td{{padding:4px 10px;border-bottom:1px solid {C['border']};}}
        </style>
        <h2>Flash Outcome</h2>
        <table>
        <tr><th>#</th><th>Result</th><th>Blocks</th><th>Duration</th><th>ECU</th></tr>
        {seq_rows_html if seq_rows_html else '<tr><td colspan=5>No flash sequences detected</td></tr>'}
        </table>
        <h2>Log Summary</h2>
        <table>
        <tr><th>Metric</th><th>Value</th></tr>
        <tr><td>CAN Frames</td><td>{len(self._can_msgs):,}</td></tr>
        <tr><td>UDS Frames Decoded</td><td>{len(self._uds_frames)}</td></tr>
        <tr><td>Flash Sequences</td><td>{len(self._sequences)}</td></tr>
        <tr><td>Programming Sessions</td><td>{prog}</td></tr>
        <tr><td>Security Access OK</td><td>{sa}</td></tr>
        <tr><td>Transfer Completed</td><td>{done}</td></tr>
        </table>
        <h2>Issue Breakdown</h2>
        <table>
        <tr><th>Severity</th><th>Count</th></tr>
        <tr><td style="color:{C['red']}">CRITICAL</td><td>{c}</td></tr>
        <tr><td style="color:{C['orange']}">ERROR</td><td>{e}</td></tr>
        <tr><td style="color:{C['amber']}">WARNING</td><td>{w}</td></tr>
        <tr><td style="color:{C['accent']}">INFO</td><td>{info}</td></tr>
        </table>
        <h2>UDS Service Counts</h2>
        <table>
        <tr><th>Service</th><th>Count</th></tr>
        {"".join(f'<tr><td>{n}</td><td>{v}</td></tr>' for n,v in sorted(svc_counts.items(), key=lambda x:-x[1])[:20])}
        </table>
        """
        self._stats_text.setHtml(html)

    # ── FILTERS ───────────────────────────────────────────────────────────────
    def _filter_issues(self):
        q   = self._issue_filter.text().lower()
        sev = self._sev_filter.currentText()
        self._issue_table.setRowCount(0)
        for issue in self._issues:
            if sev != "All" and issue.severity != sev:
                continue
            if q and not (q in issue.title.lower() or q in issue.code.lower()
                          or q in issue.service.lower()):
                continue
            self._add_issue_row(issue)

    def _filter_timeline(self):
        q        = self._tl_filter.text().lower()
        nrc_only = self._tl_nrc_only.isChecked()
        self._tl_table.setRowCount(0)
        for f in self._uds_frames:
            if nrc_only and not f.is_nrc:
                continue
            if q and not (q in f.service_name.lower() or q in f.data.hex()):
                continue
            self._add_tl_row(f)

    def _filter_raw(self):
        q = self._raw_filter.text().lower()
        self._raw_table.setRowCount(0)
        for msg in self._can_msgs[:2000]:
            if q and not (q in msg.id_str.lower() or q in msg.data_hex.lower()):
                continue
            r = self._raw_table.rowCount()
            self._raw_table.insertRow(r)
            self._raw_table.setRowHeight(r, 20)
            cells = [
                (f"{msg.timestamp:.3f}", C["text3"]),
                (str(msg.channel),       C["text2"]),
                (msg.id_str,             C["cyan"]),
                (str(len(msg.data)),     C["text2"]),
                (msg.data_hex,           C["amber"]),
                (str(msg.line_no),       C["text3"]),
            ]
            for c, (val, col) in enumerate(cells):
                it = QTableWidgetItem(val)
                it.setForeground(QBrush(QColor(col)))
                self._raw_table.setItem(r, c, it)

    # ── PDF EXPORT ─────────────────────────────────────────────────────────────
    def _export_pdf(self):
        default = os.path.splitext(self._log_path)[0] + "_UDS_RCA_Report.pdf"
        path, _ = QFileDialog.getSaveFileName(
            self, "Save PDF Report", default, "PDF Files (*.pdf)")
        if not path:
            return
        try:
            gen = PDFReportGenerator(
                issues=self._issues, sequences=self._sequences,
                uds_frames=self._uds_frames, can_msgs=self._can_msgs,
                log_path=self._log_path,
                resp_times=self._resp_times)
            gen.generate(path)
            QMessageBox.information(self, "PDF Saved",
                f"Report saved to:\n{path}\n\n"
                f"Pages: ~{6 + len(self._issues)*2}\n"
                f"Issues documented: {len(self._issues)}")
        except Exception as ex:
            QMessageBox.critical(self, "PDF Export Error", str(ex))

    # ── DRAG AND DROP ─────────────────────────────────────────────────────────
    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent):
        for url in event.mimeData().urls():
            path = url.toLocalFile()
            if os.path.isfile(path):
                self._set_log(path)
                self._start_analysis()
                break


# ═══════════════════════════════════════════════════════════════════════════════
# DEMO LOG GENERATOR  (for testing without a real log)
# ═══════════════════════════════════════════════════════════════════════════════
def generate_demo_log(path: str):
    """Generate a realistic Vector ASC log with UDS flash sequence + deliberate issues."""
    lines = [
        "date Fri Apr 19 09:00:00 2024",
        "base hex  timestamps absolute",
        "// Demo UDS Flash Log — CANvas",
        "",
    ]
    ts = 0.500
    def frame(mid, data, direction="Rx"):
        nonlocal ts
        ts += 0.002
        data_str = " ".join(f"{b:02X}" for b in data)
        return f"  {ts:.6f} 1  {mid:03X}  {direction} d {len(data)} {data_str}"

    # 1. TesterPresent
    lines.append(frame(0x7E0, [0x02, 0x3E, 0x00], "Tx"))
    lines.append(frame(0x7E8, [0x02, 0x7E, 0x00]))

    # 2. DiagnosticSessionControl — programming session
    lines.append(frame(0x7E0, [0x02, 0x10, 0x02], "Tx"))
    lines.append(frame(0x7E8, [0x06, 0x50, 0x02, 0x00, 0x19, 0x01, 0xF4]))

    # 3. CommunicationControl — disable Rx/Tx
    lines.append(frame(0x7E0, [0x03, 0x28, 0x03, 0x01], "Tx"))
    lines.append(frame(0x7E8, [0x02, 0x68, 0x03]))

    # 4. ControlDTCSetting — disable
    lines.append(frame(0x7E0, [0x02, 0x85, 0x02], "Tx"))
    lines.append(frame(0x7E8, [0x02, 0xC5, 0x02]))

    # 5. SecurityAccess — seed request
    lines.append(frame(0x7E0, [0x02, 0x27, 0x01], "Tx"))
    lines.append(frame(0x7E8, [0x06, 0x67, 0x01, 0xAB, 0xCD, 0xEF, 0x12]))

    # 6. SecurityAccess — wrong key (NRC 35)
    lines.append(frame(0x7E0, [0x06, 0x27, 0x02, 0x11, 0x22, 0x33, 0x44], "Tx"))
    lines.append(frame(0x7E8, [0x03, 0x7F, 0x27, 0x35]))    # NRC invalidKey

    # 7. TesterPresent gap (simulate long wait)
    ts += 2.5   # 2.5s gap — triggers warning
    lines.append(frame(0x7E0, [0x01, 0x3E, 0x80], "Tx"))

    # 8. EraseMemory routine
    lines.append(frame(0x7E0, [0x04, 0x31, 0x01, 0xFF, 0x00], "Tx"))
    # NRC conditions not correct
    lines.append(frame(0x7E8, [0x03, 0x7F, 0x31, 0x22]))

    # 9. RequestDownload
    lines.append(frame(0x7E0, [0x09, 0x34, 0x00, 0x44, 0x00, 0x08, 0x00, 0x00, 0x00, 0x10], "Tx"))
    # Response pending
    lines.append(frame(0x7E8, [0x03, 0x7F, 0x34, 0x78]))
    lines.append(frame(0x7E8, [0x03, 0x7F, 0x34, 0x78]))
    lines.append(frame(0x7E8, [0x04, 0x74, 0x20, 0x0F, 0xFF]))   # maxBlockLen=0x0FFF

    # 10. TransferData — block 1
    lines.append(frame(0x7E0, [0x10, 0x10, 0x36], "Tx"))   # FF start for ISO-TP
    for i in range(1, 5):
        lines.append(frame(0x7E0, [0x20 | i, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00], "Tx"))
    lines.append(frame(0x7E8, [0x02, 0x76, 0x01]))

    # 11. TransferData — wrong block counter (block 3 instead of 2)
    block_data = [0x10, 0x09, 0x36, 0x03] + [0xFF]*7   # block seq = 0x03, should be 0x02
    lines.append(frame(0x7E0, block_data[:8], "Tx"))
    lines.append(frame(0x7E8, [0x03, 0x7F, 0x36, 0x73]))  # NRC wrongBlockSequenceCounter

    # 12. P2* gap during transfer
    ts += 0.200   # 200ms gap > 150ms threshold
    lines.append(frame(0x7E0, [0x10, 0x09, 0x36, 0x02, 0x11, 0x22, 0x33, 0x44], "Tx"))
    lines.append(frame(0x7E8, [0x02, 0x76, 0x02]))

    # 13. RequestTransferExit
    lines.append(frame(0x7E0, [0x01, 0x37], "Tx"))
    lines.append(frame(0x7E8, [0x01, 0x77]))

    # 14. ECUReset — without CheckMemory (UDS-007 trigger)
    lines.append(frame(0x7E0, [0x02, 0x11, 0x01], "Tx"))
    lines.append(frame(0x7E8, [0x02, 0x51, 0x01]))

    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")


# ═══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════
def main():
    app = QApplication(sys.argv)
    app.setApplicationName("UDS Flash Analyzer")
    app.setStyle("Fusion")

    pal = QPalette()
    for role, hx in [
        (QPalette.ColorRole.Window,          C["bg"]),
        (QPalette.ColorRole.WindowText,      C["text"]),
        (QPalette.ColorRole.Base,            C["bg2"]),
        (QPalette.ColorRole.AlternateBase,   C["bg3"]),
        (QPalette.ColorRole.Text,            C["text"]),
        (QPalette.ColorRole.Button,          C["bg3"]),
        (QPalette.ColorRole.ButtonText,      C["text"]),
        (QPalette.ColorRole.Highlight,       C["accent_d"]),
        (QPalette.ColorRole.HighlightedText, "#ffffff"),
    ]:
        pal.setColor(role, QColor(hx))
    app.setPalette(pal)

    win = MainWindow()
    win.show()

    # If launched with a file argument, load it
    if len(sys.argv) > 1 and os.path.isfile(sys.argv[1]):
        win._set_log(sys.argv[1])
        QTimer.singleShot(200, win._start_analysis)
    elif "--demo" in sys.argv:
        demo_path = os.path.join(os.path.dirname(__file__), "demo_flash_log.asc")
        generate_demo_log(demo_path)
        win._set_log(demo_path)
        QTimer.singleShot(200, win._start_analysis)

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
