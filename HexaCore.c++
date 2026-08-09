#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <cstdint>
#include <atomic>
#include <cstring>
#include <algorithm>
#include <utility>

#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")

// Pencere ve Kontrol ID'leri
#define ID_BTN_CONNECT     1
#define ID_BTN_FIRST       2
#define ID_BTN_NEXT        3
#define ID_BTN_WRITE       4
#define ID_EDIT_NAME       5
#define ID_EDIT_VAL        6
#define ID_EDIT_VAL2       7
#define ID_EDIT_ADDR       8
#define ID_EDIT_NEWVAL     9
#define ID_LIST_RES        10
#define ID_LOG_BOX         11
#define ID_COMBO_SCANTYPE  12
#define ID_COMBO_VALTYPE   13
#define ID_BTN_PROCLIST    14
#define ID_PROCLIST_BOX    15
#define ID_BTN_PROCSELECT  16
#define ID_EDIT_DESC       17
#define ID_BTN_ADDLIST     18
#define ID_LIST_SAVED      19
#define ID_BTN_DELLIST     20
#define ID_BTN_SAVETABLE   21
#define ID_BTN_LOADTABLE   22
#define ID_BTN_STOPSCAN    23
#define ID_BTN_POINTERSCAN 24
#define ID_PROGRESS        25
#define ID_MENU_COPYADDR   26

// --- Yeni özellikler için ID'ler ---
#define ID_EDIT_FREEZEMS    27
#define ID_BTN_APPLYFREEZE  28
#define ID_EDIT_CHAINOFF    29
#define ID_EDIT_MAXLEVEL    30
#define ID_BTN_HEXVIEW      31
#define ID_BTN_NOPTOOL      32
#define ID_EDIT_FILTER      33
#define ID_BTN_FILTER       34
#define ID_BTN_CLEARFILTER  35
#define ID_BTN_ADDCHAIN     36
#define ID_COMBO_REGION     37

// Hex Görüntüleyici / Opcode penceresi kontrolleri
#define ID_HV_EDIT_ADDR      101
#define ID_HV_EDIT_SIZE      102
#define ID_HV_BTN_REFRESH    103
#define ID_HV_DUMP_BOX       104
#define ID_HV_EDIT_OFFSET    105
#define ID_HV_EDIT_BYTES     106
#define ID_HV_BTN_WRITE      107
#define ID_HV_OPCODE_BOX     108
#define ID_HV_EDIT_NOPOFF    109
#define ID_HV_EDIT_NOPLEN    110
#define ID_HV_BTN_NOP        111

// Arkaplan işlemlerinden ana pencereye haber vermek için özel mesajlar
#define WM_APP_PROGRESS    (WM_APP + 1)
#define WM_APP_SCANDONE    (WM_APP + 2)
#define WM_APP_POINTERDONE (WM_APP + 3)

#define TIMER_FREEZE 9001

using namespace std;

// Desteklenen Veri Tipleri ("All" seçeneği dahil)
enum ValueType {
    TYPE_BINARY = 0,
    TYPE_BYTE = 1,
    TYPE_2BYTES = 2,
    TYPE_4BYTES = 3,
    TYPE_8BYTES = 4,
    TYPE_FLOAT = 5,
    TYPE_DOUBLE = 6,
    TYPE_STRING = 7,
    TYPE_AOB = 8,
    TYPE_ALL = 9
};

struct MemoryResult {
    uintptr_t address;
    ValueType type;
    union {
        uint8_t valByte;
        int16_t val2Bytes;
        int32_t val4Bytes;
        int64_t val8Bytes;
        float   valFloat;
        double  valDouble;
    };
};

// Cheat Tablosu girdisi: normal bir adres OLABİLİR ya da bir pointer zinciri OLABİLİR
// Çoklu seviyeli pointer desteği: chainOffsets[0] modül tabanına göre statik offset,
// chainOffsets[1..n] her dereference sonrası eklenen ek offsetlerdir.
// Örn: [[base + 0x14] + 0x2C] -> chainOffsets = { 0x14, 0x2C }
struct SavedEntry {
    bool isPointer = false;
    uintptr_t address = 0;         // isPointer == false iken kullanılır
    wstring moduleName;            // isPointer == true iken kullanılır
    vector<uintptr_t> chainOffsets; // isPointer == true iken kullanılır (>=1 seviye)
    ValueType type = TYPE_4BYTES;
    wstring description;
    wstring frozenValue;
    bool frozen = false;

    // Eski tek-seviye formatla (moduleOffset/chainOffset) geriye dönük uyumluluk yardımcıları
    uintptr_t moduleOffset() const { return chainOffsets.empty() ? 0 : chainOffsets.front(); }
};

// V2: Otomatik Bölge Filtreleme (Region Filtering - Fast Scan)
// Taramayı "Tümü" yerine sadece Modül(.text/.data), Heap veya Stack bölgeleriyle
// sınırlayarak çöp sonuçları (garbage results) büyük oranda azaltır.
enum ScanRegionFilter {
    REGION_ALL = 0,
    REGION_MODULE = 1, // MEM_IMAGE (yüklü .exe/.dll görüntüleri — kod + ilişkili veri)
    REGION_HEAP = 2,   // MEM_PRIVATE ve herhangi bir thread'in stack aralığıyla ÇAKIŞMAYAN bölgeler
    REGION_STACK = 3   // MEM_PRIVATE ve bir thread'in [StackLimit, StackBase] aralığıyla ÇAKIŞAN bölgeler
};

struct ScanParams {
    double t1 = 0, t2 = 0;
    ValueType vType = TYPE_4BYTES;
    int scanType = 0;
    wstring aobPattern;
    vector<MemoryResult> baseResults; // Next Scan için anlık kopya
    int regionFilter = REGION_ALL;
    // Stack filtreleme için: taramaya başlamadan ÖNCE bir kez hesaplanır (tüm worker'lar
    // salt-okunur olarak paylaşır); [StackLimit(düşük), StackBase(yüksek)] çiftleri.
    vector<pair<uintptr_t, uintptr_t>> stackRanges;
};

struct PointerScanParams {
    uintptr_t target;
    int maxLevel = 1; // 1, 2 veya 3 seviyeli pointer araması
};

// ---- Geçmiş / Otomatik Tamamlama ----
static vector<wstring> g_addrHistory;
static vector<wstring> g_valHistory;
static const size_t HISTORY_CAP = 20;

static void AddToHistory(HWND hCombo, vector<wstring>& hist, const wstring& val) {
    if (val.empty()) return;
    for (size_t i = 0; i < hist.size(); i++) {
        if (hist[i] == val) { hist.erase(hist.begin() + i); break; }
    }
    hist.insert(hist.begin(), val);
    if (hist.size() > HISTORY_CAP) hist.resize(HISTORY_CAP);
    if (hCombo) {
        SendMessageW(hCombo, CB_RESETCONTENT, 0, 0);
        for (auto& s : hist) SendMessageW(hCombo, CB_ADDSTRING, 0, (LPARAM)s.c_str());
    }
}

// ---- Dondurma hızı (ms) ----
static int g_freezeIntervalMs = 150;

// ---- Sonuç filtresi ----
static wstring g_resultFilter;

// Global Değişkenler
HANDLE hProcess = NULL;
vector<MemoryResult> results;
vector<SavedEntry> savedEntries;
HWND hListRes, hLogBox, hEditName, hEditVal, hEditVal2, hEditAddr, hEditNewVal, hComboScanType, hComboValType;
HWND hComboRegion = NULL;
HWND hEditDesc, hListSaved, hProgressBar;
HWND hBtnFirst, hBtnNext, hBtnStop, hBtnPointer;
HWND hProcListDlg = NULL, hProcListBox = NULL;
HWND g_hMainWnd = NULL;
vector<pair<DWORD, wstring>> runningProcesses;
vector<HICON> g_procIcons; // runningProcesses ile aynı sırada, süreç simgeleri

// Yeni kontrol handle'ları
HWND hEditFreezeMs = NULL;
HWND hEditChainOff = NULL, hEditMaxLevel = NULL;
HWND hEditFilter = NULL;
HWND hHexViewDlg = NULL;

// Pencere yeniden boyutlandırıldığında/tam ekran yapıldığında konumu güncellenecek kontroller
HWND hBtnFilter = NULL, hBtnDelList = NULL, hBtnSaveTable = NULL, hBtnLoadTable = NULL, hBtnClearFilter = NULL;

HWND g_ctxMenuList = NULL;
int  g_ctxMenuIndex = -1;

atomic<bool> g_scanning(false);
atomic<bool> g_scanCancel(false);

// ---- Çoklu thread'li tarama için ilerleme sayaçları ----
// FirstScan: taranan bayt miktarını, NextScan: işlenen sonuç sayısını tutar.
// Her worker thread kendi yerel vektörüne yazdığı için sonuç birleştirmede kilit
// gerekmez; sadece bu ilerleme sayaçları thread'ler arasında paylaşılır.
atomic<uint64_t> g_scanBytesDone(0);
atomic<uint64_t> g_scanItemsDone(0);
static const unsigned MAX_SCAN_THREADS = 16; // aşırı thread oluşturmayı sınırla

WNDPROC g_oldSavedListProc = NULL;

// ---- Görsel Tema (sadece GUI, mantık aynı) ----
HFONT  hFont = NULL;      // normal etiket/kutu fontu
HFONT  hFontBold = NULL;  // buton fontu
HBRUSH hBrushBg = NULL;   // pencere zemin rengi (koyu)
HBRUSH hBrushWhite = NULL; // kart/kutu zemin rengi (artık koyu kart rengi — isim tarihi nedenlerle korundu)

// ---- Koyu tema paleti (referans görseldeki koyu lacivert + camgöbeği vurgu görünümüne yakın) ----
static const COLORREF THEME_WINDOW_BG   = RGB(15, 19, 28);   // en dış zemin (çok koyu lacivert)
static const COLORREF THEME_CARD_BG     = RGB(24, 30, 42);   // kart/panel gövdesi
static const COLORREF THEME_CARD_BORDER = RGB(52, 61, 78);   // kart kenarlığı
static const COLORREF THEME_CARD_SHADOW = RGB(8, 10, 15);    // kart gölgesi
static const COLORREF THEME_TEXT        = RGB(226, 231, 238);// normal metin (açık gri/beyaz)
static const COLORREF THEME_SELECT_HL   = RGB(38, 58, 92);   // seçili liste öğesi vurgusu
static const COLORREF THEME_DISABLED    = RGB(58, 66, 80);   // pasif buton rengi

static COLORREF Darken(COLORREF c, double factor) {
    BYTE r = (BYTE)(GetRValue(c) * factor);
    BYTE g = (BYTE)(GetGValue(c) * factor);
    BYTE b = (BYTE)(GetBValue(c) * factor);
    return RGB(r, g, b);
}

// Tüm alt kontrollere aynı fontu uygular
BOOL CALLBACK ApplyFontProc(HWND hwndChild, LPARAM lParam) {
    SendMessageW(hwndChild, WM_SETFONT, (WPARAM)lParam, TRUE);
    return TRUE;
}

// ---- Tek, tutarlı vurgu rengi: açık lacivert gradient (üstte açık, altta koyu) ----
// Önceki sürümde her panel/buton kategorisi farklı bir renk taşıyordu (mavi/teal/mor/
// yeşil/indigo/kırmızı) — bu göze dağınık ve "alakasız" göründüğü için TEK bir açık
// lacivert gradient ile değiştirildi. Artık hem panel başlıkları hem tüm butonlar aynı
// gradyanı kullanıyor; tek fark pasif (disabled) ve basılı (pressed) durumlarının
// tonu hafifçe koyulaştırması.
static const COLORREF ACCENT_GRAD_TOP    = RGB(96, 150, 214);  // açık lacivert (üst)
static const COLORREF ACCENT_GRAD_BOTTOM = RGB(48, 92, 158);   // koyu lacivert (alt)

// Dikey (yukarıdan aşağı) renk geçişini verilen dikdörtgene çizer. Yuvarlak köşeli
// alanlarda kullanmak için, çağıran taraf çizimden önce SelectClipRgn ile kırpma
// bölgesini ayarlamalı ve sonra sıfırlamalıdır.
static void FillVerticalGradient(HDC hdc, const RECT& rc, COLORREF top, COLORREF bottom) {
    int h = rc.bottom - rc.top;
    if (h < 1) h = 1;
    int rTop = GetRValue(top), gTop = GetGValue(top), bTop = GetBValue(top);
    int rBot = GetRValue(bottom), gBot = GetGValue(bottom), bBot = GetBValue(bottom);
    for (int y = 0; y < h; y++) {
        double t = (double)y / (double)h;
        BYTE r = (BYTE)(rTop + (rBot - rTop) * t);
        BYTE g = (BYTE)(gTop + (gBot - gTop) * t);
        BYTE b = (BYTE)(bTop + (bBot - bTop) * t);
        HBRUSH strip = CreateSolidBrush(RGB(r, g, b));
        RECT line = { rc.left, rc.top + y, rc.right, rc.top + y + 1 };
        FillRect(hdc, &line, strip);
        DeleteObject(strip);
    }
}

// Renkli, yuvarlak köşeli, gradyanlı butonlar çizer (owner-draw). Tüm butonlar
// aynı açık lacivert gradyanı kullanır — kategoriye göre renk değişmez.
void DrawAccentButton(LPDRAWITEMSTRUCT dis) {
    wchar_t text[64];
    GetWindowTextW(dis->hwndItem, text, 64);

    bool pressed = (dis->itemState & ODS_SELECTED) != 0;
    bool disabled = (dis->itemState & ODS_DISABLED) != 0;

    COLORREF top = ACCENT_GRAD_TOP;
    COLORREF bottom = ACCENT_GRAD_BOTTOM;
    if (disabled) {
        top = bottom = THEME_DISABLED;
    } else if (pressed) {
        top = Darken(ACCENT_GRAD_TOP, 0.78);
        bottom = Darken(ACCENT_GRAD_BOTTOM, 0.78);
    }

    HRGN btnRgn = CreateRoundRectRgn(dis->rcItem.left, dis->rcItem.top, dis->rcItem.right + 1, dis->rcItem.bottom + 1, 10, 10);
    SelectClipRgn(dis->hDC, btnRgn);
    FillVerticalGradient(dis->hDC, dis->rcItem, top, bottom);
    SelectClipRgn(dis->hDC, NULL);
    DeleteObject(btnRgn);

    // İnce, hafif koyu kenarlık (derinlik hissi için)
    HPEN borderPen = CreatePen(PS_SOLID, 1, Darken(bottom, 0.82));
    HBRUSH oldBrush = (HBRUSH)SelectObject(dis->hDC, GetStockObject(NULL_BRUSH));
    HPEN oldPen = (HPEN)SelectObject(dis->hDC, borderPen);
    RoundRect(dis->hDC, dis->rcItem.left, dis->rcItem.top, dis->rcItem.right, dis->rcItem.bottom, 10, 10);
    SelectObject(dis->hDC, oldBrush);
    SelectObject(dis->hDC, oldPen);
    DeleteObject(borderPen);

    SetBkMode(dis->hDC, TRANSPARENT);
    SetTextColor(dis->hDC, RGB(255, 255, 255));
    HFONT oldFont = (HFONT)SelectObject(dis->hDC, hFontBold);
    RECT rc = dis->rcItem;
    DrawTextW(dis->hDC, text, -1, &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    SelectObject(dis->hDC, oldFont);
}

// Bir bölüm/panel tanımı: konum, vurgu rengi ve başlık metni.
struct PanelInfo {
    RECT rc;
    const wchar_t* title;
};

static const int PANEL_HEADER_H = 30; // Renkli başlık şeridinin yüksekliği
static const int PANEL_RADIUS   = 12; // Yuvarlak köşe yarıçapı

// --- Ana pencere yerleşim sabitleri (sabit boyutlandırma/tam ekran desteği burada hesaplanır) ---
static const int LAYOUT_LEFT_X     = 20;
static const int LAYOUT_LEFT_RIGHT = 540;  // sol sütun sabit genişlikte
static const int LAYOUT_GAP        = 20;
static const int LAYOUT_RIGHT_X    = LAYOUT_LEFT_RIGHT + LAYOUT_GAP; // 560
static const int LAYOUT_MARGIN     = 20;   // pencere kenarından panele boşluk
static const int LAYOUT_DEFAULT_RIGHT_EDGE  = 1040; // varsayılan istemci genişliğinde (1060) sağ panel sınırı
static const int LAYOUT_DEFAULT_BOTTOM_EDGE = 894;  // varsayılan istemci yüksekliğinde (914) alt panel sınırı
static const int LAYOUT_MIN_RIGHT_EDGE  = LAYOUT_RIGHT_X + 320; // pencere küçültülse bile panel bozulmasın
static const int LAYOUT_MIN_BOTTOM_EDGE = 396 + 300;

// Pencere bu boyuttan (dış çerçeve dahil) daha küçük yapılamaz; böylece
// panel/kontrol yerleşimi hiçbir zaman üst üste binmez. Büyütme ve
// "Ekranı Kapla" (maximize) serbest.
static const int MAIN_WIN_MIN_W = 1100;
static const int MAIN_WIN_MIN_H = 1000;

// Ana penceredeki tüm kart/panellerin yerleşim tablosu. WM_CREATE (kontrol
// konumlandırma) ve WM_PAINT (kart çizimi) bu tabloyla senkron çalışır.
// NOT: artık const değil — pencere yeniden boyutlandırıldığında/tam ekran
// yapıldığında RelayoutMainWindow() bu tabloyu güncelliyor.
enum { PANEL_IDX_CONNECT = 0, PANEL_IDX_SCAN = 1, PANEL_IDX_WRITE = 2, PANEL_IDX_LOG = 3, PANEL_IDX_RESULTS = 4, PANEL_IDX_SAVED = 5 };
static PanelInfo g_mainPanels[] = {
    { {LAYOUT_LEFT_X,  20, LAYOUT_LEFT_RIGHT, 110}, L"Bağlantı" },
    { {LAYOUT_LEFT_X, 128, LAYOUT_LEFT_RIGHT, 378}, L"Tarama Ayarları" },
    { {LAYOUT_LEFT_X, 396, LAYOUT_LEFT_RIGHT, 726}, L"Bellek Yazma" },
    { {LAYOUT_LEFT_X, 744, LAYOUT_LEFT_RIGHT, LAYOUT_DEFAULT_BOTTOM_EDGE}, L"Log" },
    { {LAYOUT_RIGHT_X,  20, LAYOUT_DEFAULT_RIGHT_EDGE, 338}, L"Sonuçlar" },
    { {LAYOUT_RIGHT_X, 356, LAYOUT_DEFAULT_RIGHT_EDGE, LAYOUT_DEFAULT_BOTTOM_EDGE}, L"Kayıtlı Adresler (Cheat Tablosu) — kutucuk: Dondur/Çöz" },
};

// Yumuşak gölge + beyaz gövde + renkli üst şerit + başlık yazısı olan bir
// "kart" panel çizer. GROUPBOX yerine kullanılır, böylece renk ve boşluk
// tamamen bizim kontrolümüzde olur.
static void DrawCardPanel(HDC hdc, const PanelInfo& p) {
    RECT rc = p.rc;

    // Hafif gölge (kartı zeminden ayırmak için, sağ ve altta 3px kaydırılmış koyu bir kopya)
    RECT shadow = { rc.left + 3, rc.top + 3, rc.right + 3, rc.bottom + 3 };
    HBRUSH shadowBrush = CreateSolidBrush(THEME_CARD_SHADOW);
    HRGN shadowRgn = CreateRoundRectRgn(shadow.left, shadow.top, shadow.right + 1, shadow.bottom + 1, PANEL_RADIUS, PANEL_RADIUS);
    FillRgn(hdc, shadowRgn, shadowBrush);
    DeleteObject(shadowRgn);
    DeleteObject(shadowBrush);

    // Koyu kart gövdesi + ince kenarlık
    HBRUSH bodyBrush = CreateSolidBrush(THEME_CARD_BG);
    HPEN borderPen = CreatePen(PS_SOLID, 1, THEME_CARD_BORDER);
    HBRUSH oldBrush = (HBRUSH)SelectObject(hdc, bodyBrush);
    HPEN oldPen = (HPEN)SelectObject(hdc, borderPen);
    RoundRect(hdc, rc.left, rc.top, rc.right, rc.bottom, PANEL_RADIUS, PANEL_RADIUS);
    SelectObject(hdc, oldBrush);
    SelectObject(hdc, oldPen);
    DeleteObject(bodyBrush);
    DeleteObject(borderPen);

    // Başlık şeridi: tüm panellerde aynı açık lacivert gradyan (üst köşeler yuvarlak
    // kalacak şekilde kart bölgesiyle kesişim alınır). p.accent artık kullanılmıyor —
    // tutarlılık için tek bir gradyan tercih edildi.
    HRGN panelRgn = CreateRoundRectRgn(rc.left, rc.top, rc.right + 1, rc.bottom + 1, PANEL_RADIUS, PANEL_RADIUS);
    HRGN headerRgn = CreateRectRgn(rc.left, rc.top, rc.right, rc.top + PANEL_HEADER_H);
    HRGN clipRgn = CreateRectRgn(0, 0, 0, 0);
    CombineRgn(clipRgn, panelRgn, headerRgn, RGN_AND);
    SelectClipRgn(hdc, clipRgn);
    RECT headerRc = { rc.left, rc.top, rc.right, rc.top + PANEL_HEADER_H };
    FillVerticalGradient(hdc, headerRc, ACCENT_GRAD_TOP, ACCENT_GRAD_BOTTOM);
    SelectClipRgn(hdc, NULL);
    DeleteObject(panelRgn);
    DeleteObject(headerRgn);
    DeleteObject(clipRgn);

    // Başlık metni (beyaz, kalın)
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, RGB(255, 255, 255));
    HFONT oldFont = (HFONT)SelectObject(hdc, hFontBold);
    RECT textRc = { rc.left + 14, rc.top, rc.right - 10, rc.top + PANEL_HEADER_H };
    DrawTextW(hdc, p.title, -1, &textRc, DT_SINGLELINE | DT_VCENTER | DT_LEFT | DT_END_ELLIPSIS);
    SelectObject(hdc, oldFont);
}

// Pencere yeniden boyutlandırıldığında veya "Ekranı Kapla" (maximize)
// yapıldığında çağrılır: sağ sütun (Sonuçlar / Cheat Tablosu) genişlikte,
// Log ve Cheat Tablosu panelleri de yükseklikte pencereyle birlikte esner.
// Sol sütunun genişliği sabit kalır (uzun buton/etiket metinleri o sabit
// genişliğe göre tasarlandı).
// Pencere başlık çubuğunu (title bar) da koyu temaya uydurur (Windows 10 1809+/11).
// dwmapi.lib'e link zorunluluğu getirmemek için fonksiyon çalışma zamanında
// (runtime) yüklenir; API mevcut değilse sessizce hiçbir şey yapmaz.
void EnableDarkTitleBar(HWND hwnd) {
    typedef HRESULT(WINAPI* PFN_DwmSetWindowAttribute)(HWND, DWORD, LPCVOID, DWORD);
    HMODULE hDwm = LoadLibraryW(L"dwmapi.dll");
    if (!hDwm) return;
    PFN_DwmSetWindowAttribute pDwmSetWindowAttribute =
        (PFN_DwmSetWindowAttribute)GetProcAddress(hDwm, "DwmSetWindowAttribute");
    if (pDwmSetWindowAttribute) {
        const DWORD DWMWA_USE_IMMERSIVE_DARK_MODE_NEW = 20; // Win10 20H1+/Win11
        const DWORD DWMWA_USE_IMMERSIVE_DARK_MODE_OLD = 19; // Win10 1809-1909
        BOOL dark = TRUE;
        if (FAILED(pDwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE_NEW, &dark, sizeof(dark)))) {
            pDwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE_OLD, &dark, sizeof(dark));
        }
    }
    FreeLibrary(hDwm);
}

void RelayoutMainWindow(HWND hwnd) {
    if (!hwnd) return;
    RECT rc;
    GetClientRect(hwnd, &rc);
    if (rc.right <= 0 || rc.bottom <= 0) return;

    int rightEdge = rc.right - LAYOUT_MARGIN;
    if (rightEdge < LAYOUT_MIN_RIGHT_EDGE) rightEdge = LAYOUT_MIN_RIGHT_EDGE;
    int bottomEdge = rc.bottom - LAYOUT_MARGIN;
    if (bottomEdge < LAYOUT_MIN_BOTTOM_EDGE) bottomEdge = LAYOUT_MIN_BOTTOM_EDGE;

    // --- Panel tablosunu güncelle (WM_PAINT bunu kullanarak kartları çizecek) ---
    g_mainPanels[PANEL_IDX_LOG].rc.bottom     = bottomEdge;
    g_mainPanels[PANEL_IDX_RESULTS].rc.right  = rightEdge;
    g_mainPanels[PANEL_IDX_SAVED].rc.right    = rightEdge;
    g_mainPanels[PANEL_IDX_SAVED].rc.bottom   = bottomEdge;

    // --- Log paneli: sadece yüksekliği esner (genişlik sabit sol sütun) ---
    if (hLogBox) {
        int y = 782, x = 36, w = LAYOUT_LEFT_RIGHT - 16 - x;
        int h = bottomEdge - 16 - y;
        if (h < 40) h = 40;
        MoveWindow(hLogBox, x, y, w, h, TRUE);
    }

    // --- Sonuçlar paneli: filtre kutusu + buton + liste genişlikte esner ---
    int resultsRight = rightEdge - 16;
    if (hEditFilter) {
        int x = 632, y = 58;
        int w = (resultsRight - 100 - 10) - x; // Filtrele butonuna kadar
        if (w < 80) w = 80;
        MoveWindow(hEditFilter, x, y, w, 26, TRUE);
    }
    if (hBtnFilter) {
        MoveWindow(hBtnFilter, resultsRight - 100, 57, 100, 28, TRUE);
    }
    if (hListRes) {
        int x = 576, y = 100;
        int w = resultsRight - x;
        if (w < 200) w = 200;
        MoveWindow(hListRes, x, y, w, 222, TRUE);
    }

    // --- Kayıtlı Adresler paneli: liste hem genişlikte hem yükseklikte esner ---
    int savedRight = rightEdge - 16;
    int savedBottom = bottomEdge - 16;
    if (hListSaved) {
        int x = 576, y = 394;
        int w = savedRight - x;
        int h = savedBottom - 40 - y; // altta buton sırası için 40px pay
        if (w < 200) w = 200;
        if (h < 80) h = 80;
        MoveWindow(hListSaved, x, y, w, h, TRUE);
    }
    // 4 alt buton, kalan genişliğe eşit aralıklarla yayılır
    {
        int x = 576;
        int totalW = savedRight - x;
        if (totalW < 200) totalW = 200;
        int btnW = (totalW - 30) / 4; // 3 x 10px aralık
        if (btnW < 60) btnW = 60;
        int btnY = savedBottom - 30;
        HWND btns[4] = { hBtnDelList, hBtnSaveTable, hBtnLoadTable, hBtnClearFilter };
        for (int i = 0; i < 4; i++) {
            if (btns[i]) MoveWindow(btns[i], x + i * (btnW + 10), btnY, btnW, 30, TRUE);
        }
    }

    InvalidateRect(hwnd, NULL, TRUE);
}

void LogMessage(const wstring& msg) {
    wstring text = msg + L"\r\n";
    int length = GetWindowTextLengthW(hLogBox);
    SendMessageW(hLogBox, EM_SETSEL, (WPARAM)length, (LPARAM)length);
    SendMessageW(hLogBox, EM_REPLACESEL, 0, (LPARAM)text.c_str());
}


DWORD GetProcessIdByName(const wchar_t* processName) {
    DWORD processId = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);
        if (Process32FirstW(hSnapshot, &pe32)) {
            do {
                if (_wcsicmp(pe32.szExeFile, processName) == 0) {
                    processId = pe32.th32ProcessID;
                    break;
                }
            } while (Process32NextW(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
    return processId;
}

static bool IsWritableMemory(DWORD protection) {
    return protection == PAGE_READWRITE || protection == PAGE_EXECUTE_READWRITE || protection == PAGE_WRITECOPY;
}

// ---- V2: Bölge Filtreleme (Region Filtering) — Stack tespiti ----
// NtQueryInformationThread ile her thread'in TEB (Thread Environment Block) adresini
// öğrenip, TEB'in başındaki NT_TIB yapısından StackBase/StackLimit'i okuyoruz.
// Bu, Cheat Engine ve benzeri araçların da kullandığı standart, iyi belgelenmiş bir
// tekniktir (undocumented ama 20+ yıldır stabil). ntdll.dll zaten her proseste yüklü
// olduğu için ekstra link bağımlılığı gerekmez (GetProcAddress ile çalışma zamanında
// çözülür).
typedef LONG (NTAPI* PFN_NtQueryInformationThread)(HANDLE, ULONG, PVOID, ULONG, PULONG);

static PFN_NtQueryInformationThread GetNtQueryInformationThread() {
    static PFN_NtQueryInformationThread cached = NULL;
    static bool tried = false;
    if (!tried) {
        tried = true;
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (hNtdll) cached = (PFN_NtQueryInformationThread)GetProcAddress(hNtdll, "NtQueryInformationThread");
    }
    return cached;
}

// THREAD_BASIC_INFORMATION ile aynı bellek yerleşimine sahip yerel struct
// (winternl.h sürümleri arasındaki farklardan bağımsız olmak için elle tanımlandı).
struct MsThreadBasicInfo {
    LONG   ExitStatus;
    PVOID  TebBaseAddress;
    PVOID  UniqueProcess; // CLIENT_ID.UniqueProcess
    PVOID  UniqueThread;  // CLIENT_ID.UniqueThread
    ULONG_PTR AffinityMask;
    LONG   Priority;
    LONG   BasePriority;
};

// Bir thread handle'ından, hedef sürecin belleğinde okuyarak [StackLimit, StackBase]
// aralığını (düşük..yüksek adres) elde eder. Başarısızsa false döner.
static bool ReadThreadStackRange(HANDLE hThread, HANDLE hTargetProcess, uintptr_t& outLow, uintptr_t& outHigh) {
    PFN_NtQueryInformationThread pNtQIT = GetNtQueryInformationThread();
    if (!pNtQIT) return false;

    MsThreadBasicInfo tbi = {};
    ULONG retLen = 0;
    const ULONG ThreadBasicInformation = 0;
    LONG status = pNtQIT(hThread, ThreadBasicInformation, &tbi, sizeof(tbi), &retLen);
    if (status != 0 || !tbi.TebBaseAddress) return false; // 0 == STATUS_SUCCESS

    // NT_TIB (TEB'in ilk üyesi): { ExceptionList; StackBase; StackLimit; ... }
    uintptr_t tib[3] = { 0, 0, 0 };
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(hTargetProcess, tbi.TebBaseAddress, tib, sizeof(tib), &bytesRead) || bytesRead < sizeof(tib)) {
        return false;
    }

    uintptr_t stackBase = tib[1];  // yüksek adres (stack'in başlangıcı)
    uintptr_t stackLimit = tib[2]; // düşük adres (o anki commit sınırı)
    if (stackBase == 0 || stackLimit == 0) return false;
    if (stackBase < stackLimit) std::swap(stackBase, stackLimit);

    outLow = stackLimit;
    outHigh = stackBase;
    return true;
}

// Hedef sürecin TÜM thread'lerinin stack aralıklarını toplar. First Scan başlamadan
// önce (workerlar oluşturulmadan) BİR KEZ çağrılır; sonuç tüm worker'lara salt-okunur
// olarak paylaşılır.
static vector<pair<uintptr_t, uintptr_t>> GetThreadStackRanges(DWORD pid, HANDLE hTargetProcess) {
    vector<pair<uintptr_t, uintptr_t>> ranges;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return ranges;

    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
                if (hThread) {
                    uintptr_t lo = 0, hi = 0;
                    if (ReadThreadStackRange(hThread, hTargetProcess, lo, hi)) {
                        ranges.push_back({ lo, hi });
                    }
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return ranges;
}

// Verilen bellek bölgesinin herhangi bir stack aralığıyla çakışıp çakışmadığını kontrol eder.
static bool RegionOverlapsAnyStack(uintptr_t regionStart, uintptr_t regionSize, const vector<pair<uintptr_t, uintptr_t>>& stackRanges) {
    uintptr_t regionEnd = regionStart + regionSize;
    for (const auto& r : stackRanges) {
        if (regionStart < r.second && regionEnd > r.first) return true; // aralık çakışması
    }
    return false;
}

// Bir bellek bölgesinin, seçilen bölge filtresine uyup uymadığını belirler.
// (MEM_COMMIT + yazılabilirlik kontrolü zaten çağıran tarafta yapılıyor; bu sadece
// Modül/Heap/Stack ayrımını ekler.)
static bool RegionMatchesFilter(int filter, DWORD memType, uintptr_t regionStart, uintptr_t regionSize, const vector<pair<uintptr_t, uintptr_t>>& stackRanges) {
    if (filter == REGION_ALL) return true;
    if (filter == REGION_MODULE) return memType == MEM_IMAGE;
    bool isPrivate = (memType == MEM_PRIVATE);
    if (!isPrivate) return false; // Heap ve Stack sadece MEM_PRIVATE bölgelerde olur
    bool onStack = RegionOverlapsAnyStack(regionStart, regionSize, stackRanges);
    if (filter == REGION_STACK) return onStack;
    if (filter == REGION_HEAP) return !onStack;
    return true;
}

// Değer Karşılaştırma Motoru (All seçeneği için tip bazlı kontrol)
bool CompareValuesAt(void* current, double target1, double target2, ValueType type, int scanType) {
    double currVal = 0;
    if (type == TYPE_BYTE) currVal = *(uint8_t*)current;
    else if (type == TYPE_2BYTES) currVal = *(int16_t*)current;
    else if (type == TYPE_4BYTES) currVal = *(int32_t*)current;
    else if (type == TYPE_8BYTES) currVal = *(int64_t*)current;
    else if (type == TYPE_FLOAT) currVal = *(float*)current;
    else if (type == TYPE_DOUBLE) currVal = *(double*)current;

    if (scanType == 0) return currVal == target1;
    if (scanType == 1) return currVal > target1;
    if (scanType == 2) return currVal < target1;
    if (scanType == 3) return currVal >= target1 && currVal <= target2;
    if (scanType == 4) return true;
    return false;
}

wstring BuildResultLine(const MemoryResult& res) {
    wstringstream ss;
    ss << L"0x" << uppercase << hex << res.address << dec << L" | Değer: ";
    if (res.type == TYPE_BYTE) ss << (int)res.valByte;
    else if (res.type == TYPE_2BYTES) ss << res.val2Bytes;
    else if (res.type == TYPE_4BYTES) ss << res.val4Bytes;
    else if (res.type == TYPE_8BYTES) ss << res.val8Bytes;
    else if (res.type == TYPE_FLOAT) ss << res.valFloat;
    else if (res.type == TYPE_DOUBLE) ss << res.valDouble;
    else if (res.type == TYPE_AOB) ss << L"AOB Eşleşmesi";
    else ss << L"-";
    return ss.str();
}

double GetResultNumeric(const MemoryResult& res) {
    if (res.type == TYPE_BYTE) return res.valByte;
    if (res.type == TYPE_2BYTES) return res.val2Bytes;
    if (res.type == TYPE_4BYTES) return res.val4Bytes;
    if (res.type == TYPE_8BYTES) return (double)res.val8Bytes;
    if (res.type == TYPE_FLOAT) return res.valFloat;
    if (res.type == TYPE_DOUBLE) return res.valDouble;
    return 0;
}

// "48 8B ?? 89 5C 24" gibi bir AOB (Array of Bytes) örüntüsünü ayrıştırır. "?" / "??" -> joker
vector<int> ParseAOB(const wstring& text) {
    vector<int> pattern;
    wstringstream ss(text);
    wstring tok;
    while (ss >> tok) {
        if (tok == L"?" || tok == L"??") {
            pattern.push_back(-1);
        } else {
            try {
                int v = stoi(tok, nullptr, 16);
                pattern.push_back(v & 0xFF);
            } catch (...) { /* geçersiz token, atla */ }
        }
    }
    return pattern;
}

bool MatchAOB(const uint8_t* data, size_t avail, const vector<int>& pattern) {
    if (avail < pattern.size()) return false;
    for (size_t i = 0; i < pattern.size(); i++) {
        if (pattern[i] != -1 && data[i] != (uint8_t)pattern[i]) return false;
    }
    return true;
}

// Belirli bir adresteki anlık değeri okuyup metne çevirir (dondurma / listeye ekleme için)
wstring FormatMemoryValue(uintptr_t address, ValueType type) {
    if (!hProcess || address == 0) return L"0";
    size_t typeSize = 4;
    if (type == TYPE_BYTE) typeSize = 1;
    else if (type == TYPE_2BYTES) typeSize = 2;
    else if (type == TYPE_4BYTES) typeSize = 4;
    else if (type == TYPE_8BYTES) typeSize = 8;
    else if (type == TYPE_FLOAT) typeSize = 4;
    else if (type == TYPE_DOUBLE) typeSize = 8;
    else return L"0";

    vector<char> buf(typeSize);
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, (LPCVOID)address, buf.data(), typeSize, &bytesRead) || bytesRead != typeSize) return L"0";

    wstringstream ss;
    if (type == TYPE_BYTE) ss << (int)*(uint8_t*)buf.data();
    else if (type == TYPE_2BYTES) ss << *(int16_t*)buf.data();
    else if (type == TYPE_4BYTES) ss << *(int32_t*)buf.data();
    else if (type == TYPE_8BYTES) ss << *(int64_t*)buf.data();
    else if (type == TYPE_FLOAT) ss << *(float*)buf.data();
    else if (type == TYPE_DOUBLE) ss << *(double*)buf.data();
    return ss.str();
}

// Bir Cheat Tablosu girdisinin GERÇEK/GÜNCEL adresini çözer (pointer ise modülü bulup
// çoklu seviyeli zinciri dereference eder). chainOffsets = {off0, off1, ..., offN}
// addr = base + off0 ; her ara adımda: ptr = *addr ; addr = ptr + offNext ; ... ; sonuç = son addr
uintptr_t ResolveEntryAddress(const SavedEntry& e) {
    if (!e.isPointer) return e.address;
    if (!hProcess || e.chainOffsets.empty()) return 0;

    HMODULE mods[1024];
    DWORD needed = 0;
    uintptr_t base = 0;
    if (K32EnumProcessModules(hProcess, mods, sizeof(mods), &needed)) {
        int count = (int)(needed / sizeof(HMODULE));
        for (int i = 0; i < count; i++) {
            wchar_t modName[MAX_PATH];
            if (K32GetModuleBaseNameW(hProcess, mods[i], modName, MAX_PATH)) {
                if (_wcsicmp(modName, e.moduleName.c_str()) == 0) { base = (uintptr_t)mods[i]; break; }
            }
        }
    }
    if (base == 0) return 0;

    uintptr_t addr = base + e.chainOffsets[0];
    for (size_t lvl = 1; lvl < e.chainOffsets.size(); lvl++) {
        uintptr_t ptrVal = 0;
        SIZE_T br;
        if (!ReadProcessMemory(hProcess, (LPCVOID)addr, &ptrVal, sizeof(uintptr_t), &br) || br != sizeof(uintptr_t)) return 0;
        addr = ptrVal + e.chainOffsets[lvl];
    }
    return addr;
}

// Sonuç listesini (isteğe bağlı) bir metin filtresine göre yeniden doldurur.
// `results` vektörünü değiştirmez; sadece ekranda gösterileni daraltır, böylece
// Next Scan her zaman tüm sonuçlar üzerinden çalışmaya devam eder.
void RefreshResultsListFiltered() {
    if (!hListRes) return;
    SendMessageW(hListRes, LB_RESETCONTENT, 0, 0);
    wstring filterLower = g_resultFilter;
    for (auto& c : filterLower) c = towlower(c);

    int count = 0;
    for (const auto& res : results) {
        wstring line = BuildResultLine(res);
        if (!filterLower.empty()) {
            wstring lineLower = line;
            for (auto& c : lineLower) c = towlower(c);
            if (lineLower.find(filterLower) == wstring::npos) continue;
        }
        SendMessageW(hListRes, LB_ADDSTRING, 0, (LPARAM)line.c_str());
        if (++count >= 2000) break;
    }
}

void RefreshSavedList() {
    if (!hListSaved) return;
    SendMessageW(hListSaved, LB_RESETCONTENT, 0, 0);
    for (auto& e : savedEntries) {
        SendMessageW(hListSaved, LB_ADDSTRING, 0, (LPARAM)e.description.c_str());
    }
    InvalidateRect(hListSaved, NULL, TRUE);
}

// Cheat Tablosu listesindeki her satırı (kutucuk + adres + açıklama) elle çizer
void DrawSavedListItem(LPDRAWITEMSTRUCT dis) {
    if ((int)dis->itemID < 0 || dis->itemID >= savedEntries.size()) return;
    SavedEntry& e = savedEntries[dis->itemID];

    bool selected = (dis->itemState & ODS_SELECTED) != 0;
    HBRUSH bg = CreateSolidBrush(selected ? THEME_SELECT_HL : THEME_CARD_BG);
    FillRect(dis->hDC, &dis->rcItem, bg);
    DeleteObject(bg);

    RECT chk = dis->rcItem;
    chk.left += 4;
    chk.right = chk.left + 16;
    int cy = (dis->rcItem.bottom - dis->rcItem.top - 16) / 2;
    chk.top = dis->rcItem.top + cy;
    chk.bottom = chk.top + 16;
    DrawFrameControl(dis->hDC, &chk, DFC_BUTTON, DFCS_BUTTONCHECK | (e.frozen ? DFCS_CHECKED : 0));

    wstring line;
    if (e.isPointer) {
        line = L"[PTR] " + e.description;
        if (e.frozen) line += L" (Kilitli: " + e.frozenValue + L")";
    } else {
        wstringstream ss;
        ss << L"0x" << uppercase << hex << e.address << dec << L" | " << e.description;
        if (e.frozen) ss << L" (Kilitli: " << e.frozenValue << L")";
        line = ss.str();
    }

    RECT txt = dis->rcItem;
    txt.left = chk.right + 8;
    SetBkMode(dis->hDC, TRANSPARENT);
    SetTextColor(dis->hDC, THEME_TEXT);
    HFONT oldFont = (HFONT)SelectObject(dis->hDC, hFont);
    DrawTextW(dis->hDC, line.c_str(), -1, &txt, DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);
    SelectObject(dis->hDC, oldFont);
}

// Cheat Tablosu listesine tıklamaları yakalar: sol tarafa (kutucuğa) tıklanınca dondur/çöz
LRESULT CALLBACK SavedListSubclassProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_LBUTTONDOWN) {
        int x = (short)(lParam & 0xFFFF);
        int y = (short)((lParam >> 16) & 0xFFFF);
        LRESULT hit = SendMessageW(hwnd, LB_ITEMFROMPOINT, 0, MAKELPARAM(x, y));
        BOOL outside = HIWORD(hit);
        int index = LOWORD(hit);
        if (!outside && index >= 0 && index < (int)savedEntries.size() && x < 24) {
            savedEntries[index].frozen = !savedEntries[index].frozen;
            if (savedEntries[index].frozen) {
                uintptr_t addr = ResolveEntryAddress(savedEntries[index]);
                savedEntries[index].frozenValue = FormatMemoryValue(addr, savedEntries[index].type);
            }
            SendMessageW(hwnd, LB_SETCURSEL, index, 0);
            InvalidateRect(hwnd, NULL, TRUE);
            return 0;
        }
    }
    return CallWindowProcW(g_oldSavedListProc, hwnd, msg, wParam, lParam);
}

// Write Memory (silent=true iken log basmaz; dondurma döngüsü için kullanılır)
void WriteMemory(uintptr_t address, ValueType type, const wstring& valStr, bool silent = false) {
    if (!hProcess) {
        if (!silent) LogMessage(L"[-] Süreç bağlı değil!");
        return;
    }

    char buffer[8] = { 0 };
    size_t size = 4;
    string sVal(valStr.begin(), valStr.end());

    try {
        if (type == TYPE_BYTE) { uint8_t v = (uint8_t)stoi(sVal); memcpy(buffer, &v, 1); size = 1; }
        else if (type == TYPE_2BYTES) { int16_t v = (int16_t)stoi(sVal); memcpy(buffer, &v, 2); size = 2; }
        else if (type == TYPE_4BYTES) { int32_t v = stoi(sVal); memcpy(buffer, &v, 4); size = 4; }
        else if (type == TYPE_8BYTES) { int64_t v = stoll(sVal); memcpy(buffer, &v, 8); size = 8; }
        else if (type == TYPE_FLOAT) { float v = stof(sVal); memcpy(buffer, &v, 4); size = 4; }
        else if (type == TYPE_DOUBLE) { double v = stod(sVal); memcpy(buffer, &v, 8); size = 8; }
        else { if (!silent) LogMessage(L"[-] Bu tip için yazma desteklenmiyor."); return; }
    } catch (...) {
        if (!silent) LogMessage(L"[-] Geçersiz değer.");
        return;
    }

    SIZE_T bytesWritten;
    if (WriteProcessMemory(hProcess, reinterpret_cast<LPVOID>(address), buffer, size, &bytesWritten)) {
        if (!silent) LogMessage(L"[+] Başarılı! Adrese yeni değer yazıldı.");
    } else {
        if (!silent) LogMessage(L"[-] Yazma başarısız!");
    }
}

// ---- Taramaları arka planda çalıştıran thread fonksiyonları (GUI donmasın diye) ----
//
// V2: Çoklu İş Parçacıklı (Multi-Threaded) Bellek Tarama
// SYSTEM_INFO ile çekirdek sayısı öğrenilir, adres uzayı (First Scan) ya da
// önceki sonuç listesi (Next Scan) o kadar parçaya bölünür ve her parça kendi
// worker thread'inde bağımsız olarak taranır. Her worker SADECE kendi yerel
// vektörüne yazdığı için sonuçları birleştirirken kilit (mutex) gerekmez;
// paylaşılan tek şey ilerleme sayaçlarıdır (atomic).

// --- First Scan worker ---
struct FirstScanWorkerParams {
    ScanParams* shared;         // salt-okunur ortak parametreler (tüm worker'lar aynısını okur)
    const vector<int>* aobPattern; // önceden bir kez parse edilmiş, salt-okunur
    uintptr_t startAddr, endAddr;  // bu worker'ın taramaktan sorumlu olduğu adres aralığı
    vector<MemoryResult>* out;     // bu worker'a özel sonuç listesi (paylaşılmaz)
};

static void ScanRangeFirst(FirstScanWorkerParams* wp) {
    ScanParams* params = wp->shared;
    LPVOID address = (LPVOID)wp->startAddr;
    MEMORY_BASIC_INFORMATION mbi;

    while ((uintptr_t)address < wp->endAddr) {
        if (g_scanCancel.load()) break;

        if (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            // Bölge, bu worker'ın aralığını aşıyorsa taşmayı önlemek için sınırla
            uintptr_t regionStart = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
            SIZE_T regionSize = mbi.RegionSize;
            if (regionStart + regionSize > wp->endAddr) regionSize = wp->endAddr - regionStart;

            if (mbi.State == MEM_COMMIT && IsWritableMemory(mbi.Protect) && regionSize > 0 &&
                RegionMatchesFilter(params->regionFilter, mbi.Type, regionStart, regionSize, params->stackRanges)) {
                vector<char> buffer(regionSize);
                SIZE_T bytesRead;

                if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer.data(), regionSize, &bytesRead) && bytesRead >= 1) {
                    if (params->vType == TYPE_AOB) {
                        if (wp->aobPattern && !wp->aobPattern->empty()) {
                            for (SIZE_T i = 0; i + wp->aobPattern->size() <= bytesRead; i++) {
                                if (MatchAOB((uint8_t*)buffer.data() + i, bytesRead - i, *wp->aobPattern)) {
                                    MemoryResult res;
                                    res.address = regionStart + i;
                                    res.type = TYPE_AOB;
                                    wp->out->push_back(res);
                                    if (wp->out->size() >= 5000) break; // aşırı büyümeyi engelle (worker başına)
                                }
                            }
                        }
                    } else {
                        vector<ValueType> typesToScan;
                        if (params->vType == TYPE_ALL) typesToScan = { TYPE_BYTE, TYPE_2BYTES, TYPE_4BYTES, TYPE_FLOAT };
                        else typesToScan = { params->vType };

                        for (ValueType currentType : typesToScan) {
                            size_t typeSize = 4;
                            if (currentType == TYPE_BYTE) typeSize = 1;
                            else if (currentType == TYPE_2BYTES) typeSize = 2;
                            else if (currentType == TYPE_4BYTES) typeSize = 4;
                            else if (currentType == TYPE_8BYTES) typeSize = 8;
                            else if (currentType == TYPE_FLOAT) typeSize = 4;
                            else if (currentType == TYPE_DOUBLE) typeSize = 8;

                            for (SIZE_T i = 0; i + typeSize <= bytesRead; i += typeSize) {
                                void* currPtr = buffer.data() + i;
                                bool matched;
                                if (params->scanType >= 4) matched = true; // Unknown/Increased/Decreased/Changed/Unchanged -> ilk taramada taban alınır
                                else matched = CompareValuesAt(currPtr, params->t1, params->t2, currentType, params->scanType);

                                if (matched) {
                                    uintptr_t foundAddress = regionStart + i;
                                    MemoryResult res;
                                    res.address = foundAddress;
                                    res.type = currentType;
                                    if (currentType == TYPE_BYTE) res.valByte = *(uint8_t*)currPtr;
                                    else if (currentType == TYPE_2BYTES) res.val2Bytes = *(int16_t*)currPtr;
                                    else if (currentType == TYPE_4BYTES) res.val4Bytes = *(int32_t*)currPtr;
                                    else if (currentType == TYPE_8BYTES) res.val8Bytes = *(int64_t*)currPtr;
                                    else if (currentType == TYPE_FLOAT) res.valFloat = *(float*)currPtr;
                                    else if (currentType == TYPE_DOUBLE) res.valDouble = *(double*)currPtr;
                                    wp->out->push_back(res);
                                }
                            }
                        }
                    }
                }
            }
            g_scanBytesDone.fetch_add((uint64_t)mbi.RegionSize, std::memory_order_relaxed);
            address = static_cast<char*>(mbi.BaseAddress) + mbi.RegionSize;
        } else break;
    }
}

DWORD WINAPI FirstScanWorkerThread(LPVOID lp) {
    ScanRangeFirst((FirstScanWorkerParams*)lp);
    return 0;
}

DWORD WINAPI FirstScanThread(LPVOID lp) {
    ScanParams* params = (ScanParams*)lp;
    vector<MemoryResult>* out = new vector<MemoryResult>();

    if (!hProcess) {
        PostMessageW(g_hMainWnd, WM_APP_SCANDONE, (WPARAM)out, 0);
        delete params;
        return 0;
    }

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    uintptr_t maxAddr = (uintptr_t)sysInfo.lpMaximumApplicationAddress;
    if (maxAddr == 0) maxAddr = 1;

    vector<int> aobPattern;
    if (params->vType == TYPE_AOB) aobPattern = ParseAOB(params->aobPattern);

    // Stack/Heap filtresi seçiliyse, taramaya başlamadan ÖNCE (worker'lar oluşmadan)
    // tüm thread'lerin stack aralıklarını BİR KEZ hesapla; worker'lar bunu salt-okunur paylaşır.
    if (params->regionFilter == REGION_STACK || params->regionFilter == REGION_HEAP) {
        params->stackRanges = GetThreadStackRanges(GetProcessId(hProcess), hProcess);
    }

    // Çekirdek sayısı kadar (üst sınır MAX_SCAN_THREADS) worker'a böl
    unsigned workerCount = sysInfo.dwNumberOfProcessors;
    if (workerCount < 1) workerCount = 1;
    if (workerCount > MAX_SCAN_THREADS) workerCount = MAX_SCAN_THREADS;

    vector<FirstScanWorkerParams> wparams(workerCount);
    vector<HANDLE> handles;
    handles.reserve(workerCount);

    uintptr_t chunkSize = maxAddr / workerCount;
    if (chunkSize == 0) chunkSize = maxAddr;

    g_scanBytesDone.store(0);

    for (unsigned i = 0; i < workerCount; i++) {
        wparams[i].shared = params;
        wparams[i].aobPattern = &aobPattern;
        wparams[i].startAddr = (uintptr_t)i * chunkSize;
        wparams[i].endAddr = (i == workerCount - 1) ? maxAddr : (uintptr_t)(i + 1) * chunkSize;
        wparams[i].out = new vector<MemoryResult>();

        HANDLE h = CreateThread(NULL, 0, FirstScanWorkerThread, &wparams[i], 0, NULL);
        if (h) {
            handles.push_back(h);
        } else {
            // Thread oluşturma nadiren başarısız olabilir: bu parçayı senkron olarak
            // orkestratör thread'inde çalıştır, tarama yine de tamamlansın.
            ScanRangeFirst(&wparams[i]);
        }
    }

    // Tüm worker'lar bitene kadar bekle; her 150ms'de bir toplam ilerlemeyi bildir.
    DWORD waitResult;
    do {
        waitResult = handles.empty() ? WAIT_OBJECT_0
            : WaitForMultipleObjects((DWORD)handles.size(), handles.data(), TRUE, 150);
        int percent = (int)((g_scanBytesDone.load() * 100ULL) / maxAddr);
        if (percent > 100) percent = 100;
        PostMessageW(g_hMainWnd, WM_APP_PROGRESS, (WPARAM)percent, 0);
    } while (waitResult == WAIT_TIMEOUT);

    for (HANDLE h : handles) CloseHandle(h);

    // Worker sonuçlarını tek listede birleştir
    size_t totalSize = 0;
    for (auto& wp : wparams) totalSize += wp.out->size();
    out->reserve(totalSize);
    for (auto& wp : wparams) {
        out->insert(out->end(), wp.out->begin(), wp.out->end());
        delete wp.out;
    }

    PostMessageW(g_hMainWnd, WM_APP_SCANDONE, (WPARAM)out, (LPARAM)1);
    delete params;
    return 0;
}

// --- Next Scan worker ---
struct NextScanWorkerParams {
    ScanParams* shared;
    const vector<int>* aobPattern;
    size_t startIdx, endIdx; // params->baseResults içindeki [startIdx, endIdx) aralığı
    vector<MemoryResult>* out;
};

static void ScanRangeNext(NextScanWorkerParams* wp) {
    ScanParams* params = wp->shared;
    const auto& baseResults = params->baseResults;

    for (size_t idx = wp->startIdx; idx < wp->endIdx; idx++) {
        if (g_scanCancel.load()) break;
        const MemoryResult& res = baseResults[idx];

        if (res.type == TYPE_AOB) {
            if (wp->aobPattern && !wp->aobPattern->empty()) {
                vector<uint8_t> buf(wp->aobPattern->size());
                SIZE_T br;
                if (ReadProcessMemory(hProcess, (LPCVOID)res.address, buf.data(), buf.size(), &br) && br == buf.size()) {
                    if (MatchAOB(buf.data(), buf.size(), *wp->aobPattern)) wp->out->push_back(res);
                }
            }
        } else {
            size_t typeSize = 4;
            if (res.type == TYPE_BYTE) typeSize = 1;
            else if (res.type == TYPE_2BYTES) typeSize = 2;
            else if (res.type == TYPE_4BYTES) typeSize = 4;
            else if (res.type == TYPE_8BYTES) typeSize = 8;
            else if (res.type == TYPE_FLOAT) typeSize = 4;
            else if (res.type == TYPE_DOUBLE) typeSize = 8;

            vector<char> currBuf(typeSize);
            SIZE_T bytesRead;
            if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(res.address), currBuf.data(), typeSize, &bytesRead) && bytesRead == typeSize) {
                MemoryResult updatedRes = res;
                if (res.type == TYPE_BYTE) updatedRes.valByte = *(uint8_t*)currBuf.data();
                else if (res.type == TYPE_2BYTES) updatedRes.val2Bytes = *(int16_t*)currBuf.data();
                else if (res.type == TYPE_4BYTES) updatedRes.val4Bytes = *(int32_t*)currBuf.data();
                else if (res.type == TYPE_8BYTES) updatedRes.val8Bytes = *(int64_t*)currBuf.data();
                else if (res.type == TYPE_FLOAT) updatedRes.valFloat = *(float*)currBuf.data();
                else if (res.type == TYPE_DOUBLE) updatedRes.valDouble = *(double*)currBuf.data();

                bool matched = false;
                double prevVal = GetResultNumeric(res);
                double currVal = GetResultNumeric(updatedRes);

                if (params->scanType <= 3) {
                    matched = CompareValuesAt(currBuf.data(), params->t1, params->t2, res.type, params->scanType);
                } else if (params->scanType == 4) {       // Unknown initial value -> tümünü tut
                    matched = true;
                } else if (params->scanType == 5) {        // Increased
                    matched = currVal > prevVal;
                } else if (params->scanType == 6) {        // Decreased
                    matched = currVal < prevVal;
                } else if (params->scanType == 7) {         // Changed
                    matched = currVal != prevVal;
                } else if (params->scanType == 8) {         // Unchanged
                    matched = currVal == prevVal;
                }

                if (matched) wp->out->push_back(updatedRes);
            }
        }

        g_scanItemsDone.fetch_add(1, std::memory_order_relaxed);
    }
}

DWORD WINAPI NextScanWorkerThread(LPVOID lp) {
    ScanRangeNext((NextScanWorkerParams*)lp);
    return 0;
}

DWORD WINAPI NextScanThread(LPVOID lp) {
    ScanParams* params = (ScanParams*)lp;
    vector<MemoryResult>* out = new vector<MemoryResult>();

    if (!hProcess) {
        PostMessageW(g_hMainWnd, WM_APP_SCANDONE, (WPARAM)out, 0);
        delete params;
        return 0;
    }

    size_t total = params->baseResults.size();

    vector<int> aobPattern;
    if (params->vType == TYPE_AOB) aobPattern = ParseAOB(params->aobPattern);

    if (total == 0) {
        PostMessageW(g_hMainWnd, WM_APP_SCANDONE, (WPARAM)out, (LPARAM)0);
        delete params;
        return 0;
    }

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    unsigned coreCount = sysInfo.dwNumberOfProcessors;
    if (coreCount < 1) coreCount = 1;
    // Küçük listeler için gereksiz thread oluşturmayı önle (en az ~100 öğe/worker)
    unsigned workerCount = (unsigned)std::min<size_t>(coreCount, std::max<size_t>(1, total / 100));
    if (workerCount > MAX_SCAN_THREADS) workerCount = MAX_SCAN_THREADS;
    if (workerCount < 1) workerCount = 1;

    vector<NextScanWorkerParams> wparams(workerCount);
    vector<HANDLE> handles;
    handles.reserve(workerCount);

    size_t chunk = total / workerCount;
    if (chunk == 0) chunk = total;

    g_scanItemsDone.store(0);

    for (unsigned i = 0; i < workerCount; i++) {
        wparams[i].shared = params;
        wparams[i].aobPattern = &aobPattern;
        wparams[i].startIdx = (size_t)i * chunk;
        wparams[i].endIdx = (i == workerCount - 1) ? total : (size_t)(i + 1) * chunk;
        wparams[i].out = new vector<MemoryResult>();

        HANDLE h = CreateThread(NULL, 0, NextScanWorkerThread, &wparams[i], 0, NULL);
        if (h) {
            handles.push_back(h);
        } else {
            ScanRangeNext(&wparams[i]);
        }
    }

    DWORD waitResult;
    do {
        waitResult = handles.empty() ? WAIT_OBJECT_0
            : WaitForMultipleObjects((DWORD)handles.size(), handles.data(), TRUE, 150);
        int percent = (int)((g_scanItemsDone.load() * 100ULL) / (uint64_t)total);
        if (percent > 100) percent = 100;
        PostMessageW(g_hMainWnd, WM_APP_PROGRESS, (WPARAM)percent, 0);
    } while (waitResult == WAIT_TIMEOUT);

    for (HANDLE h : handles) CloseHandle(h);

    size_t totalSize = 0;
    for (auto& wp : wparams) totalSize += wp.out->size();
    out->reserve(totalSize);
    for (auto& wp : wparams) {
        out->insert(out->end(), wp.out->begin(), wp.out->end());
        delete wp.out;
    }

    PostMessageW(g_hMainWnd, WM_APP_SCANDONE, (WPARAM)out, (LPARAM)0);
    delete params;
    return 0;
}

// Belleğin okunabilir olup olmadığını hızlıca kontrol eder (crash'siz dereference için)
static bool IsReadablePointerTarget(uintptr_t addr) {
    if (addr == 0) return false;
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQueryEx(hProcess, (LPCVOID)addr, &mbi, sizeof(mbi)) != sizeof(mbi)) return false;
    if (mbi.State != MEM_COMMIT) return false;
    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return false;
    return true;
}

// Çoklu seviyeli (1, 2 veya 3 seviye) statik pointer taraması: ana modül içindeki statik
// 4-byte hizalı değerleri aday pointer olarak dener; her seviyede küçük bir offset aralığında
// hedefe ulaşıp ulaşmadığına bakar. Örn: 2. seviye -> [modül+off0] + off1 -> [bu adres] + off2 == hedef
// Zaman/iş yükünü sınırlamak için bir süre bütçesi (SCAN_TIME_BUDGET_MS) ve sonuç tavanı kullanılır.
DWORD WINAPI PointerScanThread(LPVOID lp) {
    PointerScanParams* p = (PointerScanParams*)lp;
    uintptr_t target = p->target;
    int maxLevel = p->maxLevel;
    if (maxLevel < 1) maxLevel = 1;
    if (maxLevel > 3) maxLevel = 3;

    vector<SavedEntry>* found = new vector<SavedEntry>();
    const DWORD SCAN_TIME_BUDGET_MS = 25000; // taramanın toplam süresi için üst sınır
    DWORD startTick = GetTickCount();

    // Seviye derinliğine göre offset aralığı küçültülür (performans için)
    const uintptr_t OFF_RANGE_L1 = 0x1000;
    const uintptr_t OFF_RANGE_L2 = 0x400;
    const uintptr_t OFF_RANGE_L3 = 0x200;
    const size_t MAX_RESULTS = 50;
    const size_t ptrSize = sizeof(uintptr_t);

    if (hProcess) {
        HMODULE mods[512];
        DWORD needed = 0;
        if (K32EnumProcessModules(hProcess, mods, sizeof(mods), &needed) && needed >= sizeof(HMODULE)) {
            HMODULE mainMod = mods[0]; // genelde ana .exe
            MODULEINFO mi;
            if (K32GetModuleInformation(hProcess, mainMod, &mi, sizeof(mi))) {
                wchar_t modName[MAX_PATH];
                K32GetModuleBaseNameW(hProcess, mainMod, modName, MAX_PATH);

                SIZE_T modSize = mi.SizeOfImage;
                const SIZE_T SAFETY_CAP = 64u * 1024u * 1024u;
                if (modSize > SAFETY_CAP) modSize = SAFETY_CAP;

                vector<char> buf(modSize);
                SIZE_T bytesRead = 0;
                if (ReadProcessMemory(hProcess, mi.lpBaseOfDll, buf.data(), modSize, &bytesRead) && bytesRead > 0) {
                    for (size_t i = 0; i + ptrSize <= bytesRead; i += 4) {
                        if (g_scanCancel.load()) break;
                        if (found->size() >= MAX_RESULTS) break;
                        if (GetTickCount() - startTick > SCAN_TIME_BUDGET_MS) break;

                        uintptr_t candidate = 0;
                        memcpy(&candidate, buf.data() + i, ptrSize);
                        if (candidate == 0) continue;

                        bool matchedThisCandidate = false;

                        // --- Seviye 1: candidate + off0 == target ---
                        for (uintptr_t off0 = 0; off0 < OFF_RANGE_L1; off0 += 4) {
                            if (candidate + off0 == target) {
                                SavedEntry e;
                                e.isPointer = true;
                                e.moduleName = modName;
                                e.chainOffsets = { (uintptr_t)i, off0 };
                                e.type = TYPE_4BYTES;
                                wstringstream ss;
                                ss << L"Pointer(1): " << modName << L"+0x" << hex << i << L" -> +0x" << off0 << dec;
                                e.description = ss.str();
                                e.frozen = false;
                                found->push_back(e);
                                matchedThisCandidate = true;
                                break;
                            }
                        }

                        // --- Seviye 2 ve 3: ara adres(ler)i gerçekten dereference ederek dene ---
                        if (!matchedThisCandidate && maxLevel >= 2 && found->size() < MAX_RESULTS) {
                            for (uintptr_t off1 = 0; off1 < OFF_RANGE_L2 && found->size() < MAX_RESULTS; off1 += 4) {
                                if (g_scanCancel.load()) break;
                                uintptr_t interAddr = candidate + off1;
                                if (!IsReadablePointerTarget(interAddr)) continue;

                                uintptr_t p2 = 0;
                                SIZE_T br2 = 0;
                                if (!ReadProcessMemory(hProcess, (LPCVOID)interAddr, &p2, ptrSize, &br2) || br2 != ptrSize || p2 == 0) continue;

                                for (uintptr_t off2 = 0; off2 < OFF_RANGE_L2; off2 += 4) {
                                    if (p2 + off2 == target) {
                                        SavedEntry e;
                                        e.isPointer = true;
                                        e.moduleName = modName;
                                        e.chainOffsets = { (uintptr_t)i, off1, off2 };
                                        e.type = TYPE_4BYTES;
                                        wstringstream ss;
                                        ss << L"Pointer(2): " << modName << L"+0x" << hex << i << L" -> +0x" << off1 << L" -> +0x" << off2 << dec;
                                        e.description = ss.str();
                                        e.frozen = false;
                                        found->push_back(e);
                                        matchedThisCandidate = true;
                                        break;
                                    }
                                }

                                // --- Seviye 3: bir dereference daha ---
                                if (!matchedThisCandidate && maxLevel >= 3 && found->size() < MAX_RESULTS) {
                                    for (uintptr_t off2b = 0; off2b < OFF_RANGE_L3 && found->size() < MAX_RESULTS; off2b += 4) {
                                        if (g_scanCancel.load()) break;
                                        uintptr_t interAddr2 = p2 + off2b;
                                        if (!IsReadablePointerTarget(interAddr2)) continue;

                                        uintptr_t p3 = 0;
                                        SIZE_T br3 = 0;
                                        if (!ReadProcessMemory(hProcess, (LPCVOID)interAddr2, &p3, ptrSize, &br3) || br3 != ptrSize || p3 == 0) continue;

                                        for (uintptr_t off3 = 0; off3 < OFF_RANGE_L3; off3 += 4) {
                                            if (p3 + off3 == target) {
                                                SavedEntry e;
                                                e.isPointer = true;
                                                e.moduleName = modName;
                                                e.chainOffsets = { (uintptr_t)i, off1, off2b, off3 };
                                                e.type = TYPE_4BYTES;
                                                wstringstream ss;
                                                ss << L"Pointer(3): " << modName << L"+0x" << hex << i << L" -> +0x" << off1 << L" -> +0x" << off2b << L" -> +0x" << off3 << dec;
                                                e.description = ss.str();
                                                e.frozen = false;
                                                found->push_back(e);
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        if (i % 200000 == 0) {
                            int percent = (int)(((unsigned long long)i * 100ULL) / (bytesRead > 0 ? bytesRead : 1));
                            PostMessageW(g_hMainWnd, WM_APP_PROGRESS, (WPARAM)percent, 0);
                        }
                    }
                }
            }
        }
    }

    PostMessageW(g_hMainWnd, WM_APP_POINTERDONE, (WPARAM)found, 0);
    delete p;
    return 0;
}

// ---- Cheat Tablosu Kaydet / Yükle ----

void SaveCheatTable(HWND owner) {
    wchar_t fileName[MAX_PATH] = L"cheattable.txt";
    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = owner;
    ofn.lpstrFilter = L"Metin Dosyası (*.txt)\0*.txt\0Tüm Dosyalar\0*.*\0";
    ofn.lpstrFile = fileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrDefExt = L"txt";
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;

    if (GetSaveFileNameW(&ofn)) {
        wofstream file(fileName);
        if (file.is_open()) {
            for (auto& e : savedEntries) {
                file << (e.isPointer ? 1 : 0) << L"|";
                if (e.isPointer) {
                    file << e.moduleName << L"|";
                    for (size_t k = 0; k < e.chainOffsets.size(); k++) {
                        if (k) file << L",";
                        file << hex << e.chainOffsets[k] << dec;
                    }
                } else {
                    file << hex << e.address << dec << L"|0";
                }
                file << L"|" << (int)e.type << L"|" << (e.frozen ? 1 : 0) << L"|" << e.frozenValue << L"|" << e.description << L"\n";
            }
            file.close();
            LogMessage(L"[+] Cheat tablosu kaydedildi.");
        } else {
            LogMessage(L"[-] Dosya kaydedilemedi.");
        }
    }
}

void LoadCheatTable(HWND owner) {
    wchar_t fileName[MAX_PATH] = L"";
    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = owner;
    ofn.lpstrFilter = L"Metin Dosyası (*.txt)\0*.txt\0Tüm Dosyalar\0*.*\0";
    ofn.lpstrFile = fileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;

    if (GetOpenFileNameW(&ofn)) {
        wifstream file(fileName);
        if (file.is_open()) {
            savedEntries.clear();
            wstring line;
            while (getline(file, line)) {
                if (line.empty()) continue;
                vector<wstring> parts;
                wstringstream ss(line);
                wstring part;
                while (getline(ss, part, L'|')) parts.push_back(part);

                if (parts.size() >= 6) {
                    SavedEntry e;
                    e.isPointer = (parts[0] == L"1");
                    if (e.isPointer) {
                        e.moduleName = parts[1];
                        // parts[2]: virgülle ayrılmış hex offset zinciri, örn "14,2C,8"
                        wstringstream chainSS(parts[2]);
                        wstring off;
                        while (getline(chainSS, off, L',')) {
                            if (off.empty()) continue;
                            uintptr_t v = 0;
                            wstringstream(off) >> hex >> v;
                            e.chainOffsets.push_back(v);
                        }
                        if (e.chainOffsets.empty()) e.chainOffsets.push_back(0);
                    } else {
                        wstringstream a(parts[1]); a >> hex >> e.address;
                    }
                    e.type = (ValueType)_wtoi(parts[3].c_str());
                    e.frozen = (parts[4] == L"1");
                    e.frozenValue = parts[5];
                    e.description = (parts.size() >= 7) ? parts[6] : L"(açıklama yok)";
                    savedEntries.push_back(e);
                }
            }
            file.close();
            RefreshSavedList();
            LogMessage(L"[+] Cheat tablosu yüklendi.");
        } else {
            LogMessage(L"[-] Dosya açılamadı.");
        }
    }
}

// ---- Küçük metin girişi penceresi (adres etiketleme için) ----

static wstring g_promptResult;
static bool g_promptOK = false;
static HWND g_promptEdit = NULL;

LRESULT CALLBACK MiniPromptProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_CREATE: {
        CREATESTRUCTW* cs = (CREATESTRUCTW*)lParam;
        wchar_t* label = (wchar_t*)cs->lpCreateParams;
        CreateWindowW(L"STATIC", label, WS_VISIBLE | WS_CHILD, 12, 12, 340, 20, hwnd, NULL, NULL, NULL);
        g_promptEdit = CreateWindowW(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER, 12, 36, 340, 24, hwnd, (HMENU)100, NULL, NULL);
        CreateWindowW(L"BUTTON", L"Ekle", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, 190, 72, 80, 28, hwnd, (HMENU)101, NULL, NULL);
        CreateWindowW(L"BUTTON", L"Vazgeç", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, 275, 72, 80, 28, hwnd, (HMENU)102, NULL, NULL);
        EnumChildWindows(hwnd, ApplyFontProc, (LPARAM)hFont);
        SetFocus(g_promptEdit);
        break;
    }
    case WM_COMMAND:
        if (LOWORD(wParam) == 101) {
            wchar_t buf[128];
            GetWindowTextW(g_promptEdit, buf, 128);
            g_promptResult = buf;
            g_promptOK = true;
            DestroyWindow(hwnd);
        } else if (LOWORD(wParam) == 102) {
            g_promptOK = false;
            DestroyWindow(hwnd);
        }
        break;
    case WM_DRAWITEM:
        if (((LPDRAWITEMSTRUCT)lParam)->CtlType == ODT_BUTTON) DrawAccentButton((LPDRAWITEMSTRUCT)lParam);
        break;
    case WM_CTLCOLORSTATIC: {
        HDC hdc = (HDC)wParam;
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, THEME_TEXT);
        return (LRESULT)hBrushBg;
    }
    case WM_CTLCOLOREDIT: {
        HDC hdc = (HDC)wParam;
        SetBkColor(hdc, THEME_CARD_BG);
        SetTextColor(hdc, THEME_TEXT);
        return (LRESULT)hBrushWhite;
    }
    case WM_CLOSE:
        g_promptOK = false;
        DestroyWindow(hwnd);
        break;
    default:
        return DefWindowProcW(hwnd, uMsg, wParam, lParam);
    }
    return 0;
}

// Basit "modal" metin girişi: kendi mesaj döngüsünü çalıştırır, pencere kapanınca döner.
wstring PromptTextInput(HWND parent, const wstring& title, const wstring& label, const wstring& defVal) {
    g_promptOK = false;
    g_promptResult = L"";

    static bool classRegistered = false;
    if (!classRegistered) {
        WNDCLASSW wc = {};
        wc.lpfnWndProc = MiniPromptProc;
        wc.hInstance = GetModuleHandle(NULL);
        wc.lpszClassName = L"MiniPromptClass";
        wc.hCursor = LoadCursor(NULL, IDC_ARROW);
        wc.hbrBackground = hBrushBg;
        RegisterClassW(&wc);
        classRegistered = true;
    }

    EnableWindow(parent, FALSE);

    HWND hDlg = CreateWindowExW(WS_EX_DLGMODALFRAME, L"MiniPromptClass", title.c_str(),
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
        CW_USEDEFAULT, CW_USEDEFAULT, 380, 140,
        parent, NULL, GetModuleHandle(NULL), (LPVOID)label.c_str());
    ShowWindow(hDlg, SW_SHOW);
    if (!defVal.empty()) SetWindowTextW(g_promptEdit, defVal.c_str());

    MSG msg;
    while (IsWindow(hDlg)) {
        if (!GetMessageW(&msg, NULL, 0, 0)) break;
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    EnableWindow(parent, TRUE);
    SetForegroundWindow(parent);
    return g_promptOK ? g_promptResult : L"";
}

// Süreç Listesi Penceresi
// Bir sürecin .exe dosyasından küçük simgesini çeker (yetki yoksa/başarısız olursa genel bir simge döner)
HICON GetProcessIconSmall(DWORD pid) {
    HICON hIcon = NULL;
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProc) {
        wchar_t path[MAX_PATH] = L"";
        DWORD size = MAX_PATH;
        if (QueryFullProcessImageNameW(hProc, 0, path, &size)) {
            SHFILEINFOW sfi = {};
            if (SHGetFileInfoW(path, 0, &sfi, sizeof(sfi), SHGFI_ICON | SHGFI_SMALLICON)) {
                hIcon = sfi.hIcon;
            }
        }
        CloseHandle(hProc);
    }
    if (!hIcon) {
        SHFILEINFOW sfi = {};
        if (SHGetFileInfoW(L"placeholder.exe", FILE_ATTRIBUTE_NORMAL, &sfi, sizeof(sfi), SHGFI_ICON | SHGFI_SMALLICON | SHGFI_USEFILEATTRIBUTES)) {
            hIcon = sfi.hIcon;
        }
    }
    return hIcon;
}

LRESULT CALLBACK ProcListWndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_CREATE:
        CreateWindowW(L"STATIC", L"Çalışan süreci seçip \"Open\" ile bağlanın:", WS_VISIBLE | WS_CHILD, 12, 10, 360, 18, hwnd, NULL, NULL, NULL);
        // Simgeli (owner-draw) süreç listesi
        hProcListBox = CreateWindowW(L"LISTBOX", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | LBS_NOTIFY | LBS_OWNERDRAWFIXED | LBS_HASSTRINGS | WS_VSCROLL, 12, 32, 365, 275, hwnd, (HMENU)ID_PROCLIST_BOX, NULL, NULL);
        CreateWindowW(L"BUTTON", L"Open", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, 140, 318, 110, 34, hwnd, (HMENU)ID_BTN_PROCSELECT, NULL, NULL);

        EnumChildWindows(hwnd, ApplyFontProc, (LPARAM)hFont);

        runningProcesses.clear();
        for (HICON ic : g_procIcons) if (ic) DestroyIcon(ic);
        g_procIcons.clear();
        SendMessageW(hProcListBox, LB_RESETCONTENT, 0, 0);
        {
            HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnap != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32W pe32;
                pe32.dwSize = sizeof(PROCESSENTRY32W);
                if (Process32FirstW(hSnap, &pe32)) {
                    do {
                        runningProcesses.push_back({ pe32.th32ProcessID, pe32.szExeFile });
                        g_procIcons.push_back(GetProcessIconSmall(pe32.th32ProcessID));
                        wstringstream ss;
                        ss << setfill(L'0') << setw(8) << hex << pe32.th32ProcessID << dec << L"-" << pe32.szExeFile;
                        SendMessageW(hProcListBox, LB_ADDSTRING, 0, (LPARAM)ss.str().c_str());
                    } while (Process32NextW(hSnap, &pe32));
                }
                CloseHandle(hSnap);
            }
        }
        break;

    case WM_MEASUREITEM: {
        LPMEASUREITEMSTRUCT mis = (LPMEASUREITEMSTRUCT)lParam;
        if (mis->CtlID == ID_PROCLIST_BOX) mis->itemHeight = 20;
        break;
    }

    case WM_COMMAND:
        if (LOWORD(wParam) == ID_BTN_PROCSELECT || (HIWORD(wParam) == LBN_DBLCLK && LOWORD(wParam) == ID_PROCLIST_BOX)) {
            int sel = (int)SendMessageW(hProcListBox, LB_GETCURSEL, 0, 0);
            if (sel != LB_ERR && sel < runningProcesses.size()) {
                DWORD pid = runningProcesses[sel].first;
                wstring name = runningProcesses[sel].second;

                SetWindowTextW(hEditName, name.c_str());
                if (hProcess) CloseHandle(hProcess);
                hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
                if (hProcess) {
                    wstringstream ss;
                    ss << L"[+] Süreç Seçildi & Bağlanıldı! PID: " << pid << L" (" << name << L")";
                    LogMessage(ss.str());

                    BOOL isWow64 = FALSE;
                    IsWow64Process(hProcess, &isWow64);
#ifdef _WIN64
                    if (isWow64) LogMessage(L"[!] UYARI: Hedef süreç 32-bit (WOW64) görünüyor, bu araç 64-bit. Bazı sonuçlar hatalı olabilir.");
#else
                    if (!isWow64) LogMessage(L"[!] UYARI: Bu araç 32-bit derlenmiş; hedef 64-bit bir süreç olabilir.");
#endif
                } else {
                    LogMessage(L"[-] Seçilen sürece erişilemedi (Yönetici gerekebilir).");
                }
                DestroyWindow(hwnd);
                hProcListDlg = NULL;
            }
        }
        break;

    case WM_DRAWITEM: {
        LPDRAWITEMSTRUCT dis = (LPDRAWITEMSTRUCT)lParam;
        if (dis->CtlType == ODT_BUTTON) {
            DrawAccentButton(dis);
        } else if (dis->CtlType == ODT_LISTBOX && dis->CtlID == ID_PROCLIST_BOX) {
            bool selected = (dis->itemState & ODS_SELECTED) != 0;
            HBRUSH bg = CreateSolidBrush(selected ? THEME_SELECT_HL : THEME_CARD_BG);
            FillRect(dis->hDC, &dis->rcItem, bg);
            DeleteObject(bg);

            if ((int)dis->itemID >= 0 && dis->itemID < g_procIcons.size() && g_procIcons[dis->itemID]) {
                int iconY = dis->rcItem.top + (dis->rcItem.bottom - dis->rcItem.top - 16) / 2;
                DrawIconEx(dis->hDC, dis->rcItem.left + 4, iconY, g_procIcons[dis->itemID], 16, 16, 0, NULL, DI_NORMAL);
            }

            wchar_t text[256] = L"";
            SendMessageW(dis->hwndItem, LB_GETTEXT, dis->itemID, (LPARAM)text);

            RECT txt = dis->rcItem;
            txt.left += 26;
            SetBkMode(dis->hDC, TRANSPARENT);
            SetTextColor(dis->hDC, THEME_TEXT);
            HFONT oldFont = (HFONT)SelectObject(dis->hDC, hFont);
            DrawTextW(dis->hDC, text, -1, &txt, DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);
            SelectObject(dis->hDC, oldFont);
        }
        break;
    }

    case WM_CTLCOLORSTATIC: {
        HDC hdc = (HDC)wParam;
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, THEME_TEXT);
        return (LRESULT)hBrushBg;
    }
    case WM_CTLCOLORLISTBOX: {
        HDC hdc = (HDC)wParam;
        SetBkColor(hdc, THEME_CARD_BG);
        SetTextColor(hdc, THEME_TEXT);
        return (LRESULT)hBrushWhite;
    }

    case WM_DESTROY:
        for (HICON ic : g_procIcons) if (ic) DestroyIcon(ic);
        g_procIcons.clear();
        hProcListDlg = NULL;
        break;

    default:
        return DefWindowProcW(hwnd, uMsg, wParam, lParam);
    }
    return 0;
}

// =====================================================================================
// ---- Bellek Görüntüleyicisi (Hex Editor) + Basit Opcode Okuyucu + NOP/Patch Aracı ----
// =====================================================================================

struct HexViewState {
    uintptr_t baseAddr = 0;
    int blockSize = 256;
};

// Ham baytlardan hex + ASCII dökümü metni üretir (16 bayt/satır)
wstring BuildHexDump(uintptr_t base, int size) {
    if (!hProcess || size <= 0) return L"(okunamadı)";
    vector<uint8_t> buf(size);
    SIZE_T br = 0;
    if (!ReadProcessMemory(hProcess, (LPCVOID)base, buf.data(), size, &br) || br == 0) {
        return L"(bellek okunamadı - adresi/izinleri kontrol edin)";
    }
    wstringstream ss;
    for (size_t i = 0; i < br; i += 16) {
        ss << L"0x" << uppercase << hex << setw((int)sizeof(uintptr_t) * 2) << setfill(L'0') << (unsigned long long)(base + i) << L"  ";
        wstring ascii;
        for (size_t j = i; j < i + 16; j++) {
            if (j < br) {
                ss << setw(2) << setfill(L'0') << (int)buf[j] << L" ";
                wchar_t c = (wchar_t)buf[j];
                ascii += (c >= 32 && c < 127) ? c : L'.';
            } else {
                ss << L"   ";
            }
        }
        ss << L" | " << ascii << L"\r\n";
    }
    ss << dec;
    return ss.str();
}

// ModRM (+ olası SIB + yer değiştirme) baytlarının toplam uzunluğunu hesaplar
static int ModRMLength(const uint8_t* p, size_t avail, int& dispSize, bool& hasSIB) {
    dispSize = 0; hasSIB = false;
    if (avail < 1) return 0;
    uint8_t modrm = p[0];
    int mod = (modrm >> 6) & 3;
    int rm = modrm & 7;
    int len = 1;
    if (mod != 3 && rm == 4) {
        hasSIB = true;
        if (avail < 2) return len;
        len += 1;
        uint8_t sib = p[1];
        int base = sib & 7;
        if (mod == 0 && base == 5) dispSize = 4;
    }
    if (mod == 0 && rm == 5 && !hasSIB) dispSize = 4; // RIP-relative / disp32
    else if (mod == 1) dispSize = 1;
    else if (mod == 2) dispSize = 4;
    len += dispSize;
    return len;
}

// Çok basit / YAKLAŞIK bir x86-64 komut uzunluğu hesaplayıcı.
// Tam bir disassembler DEĞİLDİR; sadece ham baytları kabaca komut sınırlarına ayırıp
// hex dökümünü okunabilir kılmak ve NOP/patch aracına "bir sonraki komuta kadar" gibi
// bir referans vermek için kullanılır. Tanınmayan opcode'larda güvenli şekilde 1 bayt döner.
static int DecodeApproxInstrLength(const uint8_t* p, size_t avail) {
    if (avail == 0) return 1;
    size_t i = 0;
    bool rex = false;

    while (i < avail) {
        uint8_t b = p[i];
        if (b == 0x66 || b == 0x67 || b == 0xF0 || b == 0xF2 || b == 0xF3 ||
            b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 || b == 0x64 || b == 0x65) {
            i++; continue;
        }
        if (b >= 0x40 && b <= 0x4F) { rex = true; i++; continue; }
        break;
    }
    if (i >= avail) return (int)(i > 0 ? i : 1);

    uint8_t op = p[i]; i++;
    bool needModRM = false;
    int immSize = 0;

    if (op == 0x0F) {
        if (i >= avail) return (int)i;
        uint8_t op2 = p[i]; i++;
        if (op2 >= 0x80 && op2 <= 0x8F) immSize = 4;      // Jcc near
        else needModRM = true;                            // çoğu 0F xx ModRM alır
    }
    else if (op >= 0x70 && op <= 0x7F) immSize = 1;        // Jcc short
    else if (op == 0xEB) immSize = 1;                      // JMP short
    else if (op == 0xE9 || op == 0xE8) immSize = 4;        // JMP/CALL near rel32
    else if (op == 0xC2) immSize = 2;                      // RET imm16
    else if (op == 0x68) immSize = 4;                      // PUSH imm32
    else if (op == 0x6A) immSize = 1;                      // PUSH imm8
    else if (op >= 0xB0 && op <= 0xB7) immSize = 1;        // MOV r8, imm8
    else if (op >= 0xB8 && op <= 0xBF) immSize = rex ? 8 : 4; // MOV r, imm
    else if (op == 0xA8) immSize = 1;
    else if (op == 0xA9) immSize = 4;
    else if (op == 0x80 || op == 0x82 || op == 0x83 || op == 0x6B || op == 0xC0 || op == 0xC1 || op == 0xC6) { needModRM = true; immSize = 1; }
    else if (op == 0x81 || op == 0x69 || op == 0xC7) { needModRM = true; immSize = 4; }
    else if ((op <= 0x3D && (op & 0x07) <= 5) ||
             (op >= 0x84 && op <= 0x8F) || op == 0x63 ||
             (op >= 0xD0 && op <= 0xD3) || op == 0xF6 || op == 0xF7 ||
             op == 0xFE || op == 0xFF || op == 0x8D) {
        needModRM = true;
        if (op == 0xF6) immSize = 1;
        if (op == 0xF7) immSize = 4;
    }
    // Diğer tüm opcode'lar (90 NOP, C3 RET, CC INT3, 50-5F PUSH/POP reg, vb.) tek bayt kabul edilir.

    if (needModRM) {
        int dispSize = 0; bool hasSIB = false;
        int mlen = ModRMLength(p + i, avail - i, dispSize, hasSIB);
        if (mlen <= 0) mlen = 1;
        i += mlen;
    }
    i += immSize;
    if (i > avail) i = avail;
    if (i == 0) i = 1;
    return (int)i;
}

// Yaklaşık komut sınırlarına göre "adres [uzunluk] hex baytlar" listesi üretir
wstring BuildOpcodeView(uintptr_t base, int size) {
    if (!hProcess || size <= 0) return L"(okunamadı)";
    vector<uint8_t> buf(size);
    SIZE_T br = 0;
    if (!ReadProcessMemory(hProcess, (LPCVOID)base, buf.data(), size, &br) || br == 0) {
        return L"(bellek okunamadı)";
    }
    wstringstream ss;
    size_t off = 0;
    int lines = 0;
    while (off < br && lines < 80) {
        int len = DecodeApproxInstrLength(buf.data() + off, br - off);
        if (len <= 0) len = 1;
        ss << L"0x" << uppercase << hex << setw((int)sizeof(uintptr_t) * 2) << setfill(L'0') << (unsigned long long)(base + off)
           << L"  [" << dec << setw(2) << setfill(L' ') << len << L" bayt]  ";
        for (int k = 0; k < len && (off + (size_t)k) < br; k++) {
            ss << uppercase << hex << setw(2) << setfill(L'0') << (int)buf[off + k] << L" ";
        }
        ss << dec << L"\r\n";
        off += (size_t)len;
        lines++;
    }
    return ss.str();
}

// "90 90 EB 05" gibi boşlukla ayrılmış hex bayt dizisini ayrıştırır
vector<uint8_t> ParseHexBytes(const wstring& text) {
    vector<uint8_t> out;
    wstringstream ss(text);
    wstring tok;
    while (ss >> tok) {
        try {
            int v = stoi(tok, nullptr, 16);
            out.push_back((uint8_t)(v & 0xFF));
        } catch (...) { /* geçersiz token, atla */ }
    }
    return out;
}

// Hedef süreçte, korumayı geçici olarak RWX yapıp bayt(lar)ı yazar, sonra korumayı geri alır.
// Bu, "inline hook" / kod yaması (örn. bir komutu NOP'lamak) için gerekli temel işlemdir.
bool PatchBytesAt(uintptr_t addr, const vector<uint8_t>& bytes) {
    if (!hProcess || bytes.empty() || addr == 0) return false;
    DWORD oldProtect = 0;
    if (!VirtualProtectEx(hProcess, (LPVOID)addr, bytes.size(), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return false;
    }
    SIZE_T written = 0;
    bool ok = WriteProcessMemory(hProcess, (LPVOID)addr, bytes.data(), bytes.size(), &written) && written == bytes.size();
    DWORD tmp;
    VirtualProtectEx(hProcess, (LPVOID)addr, bytes.size(), oldProtect, &tmp);
    return ok;
}

void RefreshHexViewerContent(HWND hwnd) {
    HexViewState* st = (HexViewState*)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
    if (!st) return;
    SetWindowTextW(GetDlgItem(hwnd, ID_HV_DUMP_BOX), BuildHexDump(st->baseAddr, st->blockSize).c_str());
    int opSize = st->blockSize < 512 ? st->blockSize : 512;
    SetWindowTextW(GetDlgItem(hwnd, ID_HV_OPCODE_BOX), BuildOpcodeView(st->baseAddr, opSize).c_str());
}

LRESULT CALLBACK HexViewWndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_CREATE: {
        CREATESTRUCTW* cs = (CREATESTRUCTW*)lParam;
        HexViewState* st = new HexViewState();
        st->baseAddr = (uintptr_t)cs->lpCreateParams;
        st->blockSize = 256;
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)st);

        CreateWindowW(L"STATIC", L"Adres (hex):", WS_VISIBLE | WS_CHILD, 12, 12, 80, 20, hwnd, NULL, NULL, NULL);
        HWND hAddr = CreateWindowW(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER, 95, 10, 140, 22, hwnd, (HMENU)ID_HV_EDIT_ADDR, NULL, NULL);
        { wstringstream ss; ss << uppercase << hex << (unsigned long long)st->baseAddr; SetWindowTextW(hAddr, ss.str().c_str()); }

        CreateWindowW(L"STATIC", L"Boyut:", WS_VISIBLE | WS_CHILD, 245, 12, 45, 20, hwnd, NULL, NULL, NULL);
        CreateWindowW(L"EDIT", L"256", WS_VISIBLE | WS_CHILD | WS_BORDER, 292, 10, 55, 22, hwnd, (HMENU)ID_HV_EDIT_SIZE, NULL, NULL);
        CreateWindowW(L"BUTTON", L"Yenile", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, 358, 9, 80, 24, hwnd, (HMENU)ID_HV_BTN_REFRESH, NULL, NULL);

        CreateWindowW(L"BUTTON", L"Hex + ASCII Görünümü", WS_VISIBLE | WS_CHILD | BS_GROUPBOX, 12, 42, 590, 190, hwnd, NULL, NULL, NULL);
        CreateWindowW(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_MULTILINE | ES_READONLY | WS_VSCROLL | ES_AUTOVSCROLL, 20, 64, 574, 160, hwnd, (HMENU)ID_HV_DUMP_BOX, NULL, NULL);

        CreateWindowW(L"BUTTON", L"Bayt Düzenle", WS_VISIBLE | WS_CHILD | BS_GROUPBOX, 12, 240, 590, 80, hwnd, NULL, NULL, NULL);
        CreateWindowW(L"STATIC", L"Ofset(hex,bloğun başından):", WS_VISIBLE | WS_CHILD, 22, 264, 170, 18, hwnd, NULL, NULL, NULL);
        CreateWindowW(L"EDIT", L"0", WS_VISIBLE | WS_CHILD | WS_BORDER, 195, 261, 70, 22, hwnd, (HMENU)ID_HV_EDIT_OFFSET, NULL, NULL);
        CreateWindowW(L"STATIC", L"Yeni Baytlar (hex, boşluklu):", WS_VISIBLE | WS_CHILD, 22, 292, 170, 18, hwnd, NULL, NULL, NULL);
        CreateWindowW(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER, 195, 289, 300, 22, hwnd, (HMENU)ID_HV_EDIT_BYTES, NULL, NULL);
        CreateWindowW(L"BUTTON", L"Yaz", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, 505, 288, 80, 24, hwnd, (HMENU)ID_HV_BTN_WRITE, NULL, NULL);

        CreateWindowW(L"BUTTON", L"Basit Opcode / Disassembler (yaklaşık)", WS_VISIBLE | WS_CHILD | BS_GROUPBOX, 12, 328, 590, 190, hwnd, NULL, NULL, NULL);
        CreateWindowW(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_MULTILINE | ES_READONLY | WS_VSCROLL | ES_AUTOVSCROLL, 20, 350, 574, 160, hwnd, (HMENU)ID_HV_OPCODE_BOX, NULL, NULL);

        CreateWindowW(L"BUTTON", L"NOP / Patch Aracı", WS_VISIBLE | WS_CHILD | BS_GROUPBOX, 12, 526, 590, 80, hwnd, NULL, NULL, NULL);
        CreateWindowW(L"STATIC", L"Ofset(hex):", WS_VISIBLE | WS_CHILD, 22, 550, 65, 18, hwnd, NULL, NULL, NULL);
        CreateWindowW(L"EDIT", L"0", WS_VISIBLE | WS_CHILD | WS_BORDER, 90, 547, 70, 22, hwnd, (HMENU)ID_HV_EDIT_NOPOFF, NULL, NULL);
        CreateWindowW(L"STATIC", L"Uzunluk(bayt):", WS_VISIBLE | WS_CHILD, 175, 550, 85, 18, hwnd, NULL, NULL, NULL);
        CreateWindowW(L"EDIT", L"1", WS_VISIBLE | WS_CHILD | WS_BORDER, 262, 547, 50, 22, hwnd, (HMENU)ID_HV_EDIT_NOPLEN, NULL, NULL);
        CreateWindowW(L"BUTTON", L"Seçili Aralığı NOP Yap (0x90)", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, 330, 545, 255, 26, hwnd, (HMENU)ID_HV_BTN_NOP, NULL, NULL);

        EnumChildWindows(hwnd, ApplyFontProc, (LPARAM)hFont);
        RefreshHexViewerContent(hwnd);
        break;
    }
    case WM_COMMAND:
        if (LOWORD(wParam) == ID_HV_BTN_REFRESH) {
            HexViewState* st = (HexViewState*)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
            wchar_t addrBuf[32], sizeBuf[16];
            GetWindowTextW(GetDlgItem(hwnd, ID_HV_EDIT_ADDR), addrBuf, 32);
            GetWindowTextW(GetDlgItem(hwnd, ID_HV_EDIT_SIZE), sizeBuf, 16);
            uintptr_t a = 0; wistringstream(addrBuf) >> hex >> a;
            int sz = _wtoi(sizeBuf);
            if (sz <= 0) sz = 256;
            if (sz > 8192) sz = 8192; // aşırı büyük okumaları engelle
            st->baseAddr = a; st->blockSize = sz;
            RefreshHexViewerContent(hwnd);
        }
        else if (LOWORD(wParam) == ID_HV_BTN_WRITE) {
            HexViewState* st = (HexViewState*)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
            wchar_t offBuf[32], bytesBuf[512];
            GetWindowTextW(GetDlgItem(hwnd, ID_HV_EDIT_OFFSET), offBuf, 32);
            GetWindowTextW(GetDlgItem(hwnd, ID_HV_EDIT_BYTES), bytesBuf, 512);
            uintptr_t off = 0; wistringstream(offBuf) >> hex >> off;
            vector<uint8_t> bytes = ParseHexBytes(bytesBuf);
            if (bytes.empty()) {
                MessageBoxW(hwnd, L"Geçerli hex bayt girin (örn: 90 90 90).", L"Hata", MB_ICONWARNING);
            } else if (PatchBytesAt(st->baseAddr + off, bytes)) {
                LogMessage(L"[+] Bayt(lar) yazıldı (Hex Görüntüleyici).");
                RefreshHexViewerContent(hwnd);
            } else {
                MessageBoxW(hwnd, L"Yazma başarısız oldu (bellek korumalı olabilir).", L"Hata", MB_ICONERROR);
            }
        }
        else if (LOWORD(wParam) == ID_HV_BTN_NOP) {
            HexViewState* st = (HexViewState*)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
            wchar_t offBuf[32], lenBuf[16];
            GetWindowTextW(GetDlgItem(hwnd, ID_HV_EDIT_NOPOFF), offBuf, 32);
            GetWindowTextW(GetDlgItem(hwnd, ID_HV_EDIT_NOPLEN), lenBuf, 16);
            uintptr_t off = 0; wistringstream(offBuf) >> hex >> off;
            int len = _wtoi(lenBuf);
            if (len <= 0) len = 1;
            if (len > 64) len = 64; // tek seferde aşırı büyük yamaları engelle
            vector<uint8_t> nops((size_t)len, 0x90);
            if (PatchBytesAt(st->baseAddr + off, nops)) {
                wstringstream ss; ss << L"[+] " << len << L" bayt NOP (0x90) ile dolduruldu.";
                LogMessage(ss.str());
                RefreshHexViewerContent(hwnd);
            } else {
                MessageBoxW(hwnd, L"NOP yazma başarısız oldu.", L"Hata", MB_ICONERROR);
            }
        }
        break;
    case WM_DRAWITEM:
        if (((LPDRAWITEMSTRUCT)lParam)->CtlType == ODT_BUTTON) DrawAccentButton((LPDRAWITEMSTRUCT)lParam);
        break;
    case WM_CTLCOLORSTATIC: {
        HDC hdc = (HDC)wParam;
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, THEME_TEXT);
        return (LRESULT)hBrushBg;
    }
    case WM_CTLCOLOREDIT: {
        HDC hdc = (HDC)wParam;
        SetBkColor(hdc, THEME_CARD_BG);
        SetTextColor(hdc, THEME_TEXT);
        return (LRESULT)hBrushWhite;
    }
    case WM_DESTROY: {
        HexViewState* st = (HexViewState*)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
        delete st;
        hHexViewDlg = NULL;
        break;
    }
    default:
        return DefWindowProcW(hwnd, uMsg, wParam, lParam);
    }
    return 0;
}

void OpenHexViewer(HWND parent, uintptr_t address) {
    static bool classRegistered = false;
    if (!classRegistered) {
        WNDCLASSW wc = {};
        wc.lpfnWndProc = HexViewWndProc;
        wc.hInstance = GetModuleHandle(NULL);
        wc.lpszClassName = L"HexViewerWindowClass";
        wc.hCursor = LoadCursor(NULL, IDC_ARROW);
        wc.hbrBackground = hBrushBg;
        RegisterClassW(&wc);
        classRegistered = true;
    }
    if (hHexViewDlg) {
        DestroyWindow(hHexViewDlg);
        hHexViewDlg = NULL;
    }
    hHexViewDlg = CreateWindowExW(0, L"HexViewerWindowClass", L"Hex Görüntüleyici / Disassembler / NOP Aracı",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 630, 660,
        parent, NULL, GetModuleHandle(NULL), (LPVOID)address);
    ShowWindow(hHexViewDlg, SW_SHOW);
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_CREATE:
        // NOT: Bölüm çerçeveleri artık GROUPBOX değil; renkli/yuvarlak "kart" panelleri
        // WM_PAINT içinde g_mainPanels tablosuna göre çiziliyor. Aşağıdaki koordinatlar
        // o tablodaki panel sınırlarıyla eşleşecek şekilde, aralarında bolca boşlukla
        // (nefes payı) yerleştirildi. Sağ sütun (Sonuçlar / Cheat Tablosu) ve Log paneli
        // RelayoutMainWindow() tarafından pencere yeniden boyutlandırıldığında/tam ekran
        // yapıldığında otomatik esner.

        // --- Panel: Bağlantı ---
        CreateWindowW(L"STATIC", L"Process:", WS_VISIBLE | WS_CHILD, 36, 62, 64, 20, hwnd, NULL, NULL, NULL);
        hEditName = CreateWindowW(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER, 108, 58, 150, 26, hwnd, (HMENU)ID_EDIT_NAME, NULL, NULL);
        CreateWindowW(L"BUTTON", L"Bağlan", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, 268, 57, 85, 28, hwnd, (HMENU)ID_BTN_CONNECT, NULL, NULL);
        CreateWindowW(L"BUTTON", L"Process List", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, 361, 57, 95, 28, hwnd, (HMENU)ID_BTN_PROCLIST, NULL, NULL);

        // --- Panel: Tarama Ayarları ---
        CreateWindowW(L"STATIC", L"Value Type:", WS_VISIBLE | WS_CHILD, 36, 170, 85, 20, hwnd, NULL, NULL, NULL);
        hComboValType = CreateWindowW(L"COMBOBOX", L"", WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST | WS_VSCROLL, 126, 166, 150, 200, hwnd, (HMENU)ID_COMBO_VALTYPE, NULL, NULL);
        SendMessageW(hComboValType, CB_ADDSTRING, 0, (LPARAM)L"Binary");
        SendMessageW(hComboValType, CB_ADDSTRING, 0, (LPARAM)L"Byte");
        SendMessageW(hComboValType, CB_ADDSTRING, 0, (LPARAM)L"2 Bytes");
        SendMessageW(hComboValType, CB_ADDSTRING, 0, (LPARAM)L"4 Bytes");
        SendMessageW(hComboValType, CB_ADDSTRING, 0, (LPARAM)L"8 Bytes");
        SendMessageW(hComboValType, CB_ADDSTRING, 0, (LPARAM)L"Float");
        SendMessageW(hComboValType, CB_ADDSTRING, 0, (LPARAM)L"Double");
        SendMessageW(hComboValType, CB_ADDSTRING, 0, (LPARAM)L"String");
        SendMessageW(hComboValType, CB_ADDSTRING, 0, (LPARAM)L"Array of byte");
        SendMessageW(hComboValType, CB_ADDSTRING, 0, (LPARAM)L"All"); // <-- All Eklendi
        SendMessageW(hComboValType, CB_SETCURSEL, 3, 0); // Varsayılan 4 Bytes

        CreateWindowW(L"STATIC", L"Scan Type:", WS_VISIBLE | WS_CHILD, 296, 170, 75, 20, hwnd, NULL, NULL, NULL);
        hComboScanType = CreateWindowW(L"COMBOBOX", L"", WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST | WS_VSCROLL, 376, 166, 148, 200, hwnd, (HMENU)ID_COMBO_SCANTYPE, NULL, NULL);
        SendMessageW(hComboScanType, CB_ADDSTRING, 0, (LPARAM)L"Exact Value");
        SendMessageW(hComboScanType, CB_ADDSTRING, 0, (LPARAM)L"Bigger than...");
        SendMessageW(hComboScanType, CB_ADDSTRING, 0, (LPARAM)L"Smaller than...");
        SendMessageW(hComboScanType, CB_ADDSTRING, 0, (LPARAM)L"Value between...");
        SendMessageW(hComboScanType, CB_ADDSTRING, 0, (LPARAM)L"Unknown initial value");
        SendMessageW(hComboScanType, CB_ADDSTRING, 0, (LPARAM)L"Increased value");
        SendMessageW(hComboScanType, CB_ADDSTRING, 0, (LPARAM)L"Decreased value");
        SendMessageW(hComboScanType, CB_ADDSTRING, 0, (LPARAM)L"Changed value");
        SendMessageW(hComboScanType, CB_ADDSTRING, 0, (LPARAM)L"Unchanged value");
        SendMessageW(hComboScanType, CB_SETCURSEL, 0, 0);

        // V2: Bölge Filtreleme (Region Filtering) — sadece Modül/Heap/Stack taransın, çöp sonuçlar azalsın
        CreateWindowW(L"STATIC", L"Bölge:", WS_VISIBLE | WS_CHILD, 36, 204, 55, 18, hwnd, NULL, NULL, NULL);
        hComboRegion = CreateWindowW(L"COMBOBOX", L"", WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST | WS_VSCROLL, 96, 200, 210, 200, hwnd, (HMENU)ID_COMBO_REGION, NULL, NULL);
        SendMessageW(hComboRegion, CB_ADDSTRING, 0, (LPARAM)L"Tümü");
        SendMessageW(hComboRegion, CB_ADDSTRING, 0, (LPARAM)L"Sadece Modül (.text/.data)");
        SendMessageW(hComboRegion, CB_ADDSTRING, 0, (LPARAM)L"Sadece Heap (Yığın)");
        SendMessageW(hComboRegion, CB_ADDSTRING, 0, (LPARAM)L"Sadece Stack (Çağrı Yığını)");
        SendMessageW(hComboRegion, CB_SETDROPPEDWIDTH, 260, 0); // uzun etiketler kapalı kutuyu değil sadece açılır listeyi genişletsin
        SendMessageW(hComboRegion, CB_SETCURSEL, 0, 0); // Varsayılan: Tümü

        CreateWindowW(L"STATIC", L"Value:", WS_VISIBLE | WS_CHILD, 36, 244, 50, 20, hwnd, NULL, NULL, NULL);
        // Değer geçmişi için normal EDIT yerine düzenlenebilir COMBOBOX kullanılıyor (Hızlı Değer Filtreleme kısayolları ile birlikte)
        hEditVal = CreateWindowW(L"COMBOBOX", L"", WS_VISIBLE | WS_CHILD | CBS_DROPDOWN | CBS_AUTOHSCROLL | WS_VSCROLL, 96, 240, 170, 220, hwnd, (HMENU)ID_EDIT_VAL, NULL, NULL);
        hEditVal2 = CreateWindowW(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER, 276, 240, 170, 26, hwnd, (HMENU)ID_EDIT_VAL2, NULL, NULL);

        hBtnFirst = CreateWindowW(L"BUTTON", L"First Scan (F2)", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, 36, 274, 200, 34, hwnd, (HMENU)ID_BTN_FIRST, NULL, NULL);
        hBtnNext = CreateWindowW(L"BUTTON", L"Next Scan (F3)", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, 248, 274, 200, 34, hwnd, (HMENU)ID_BTN_NEXT, NULL, NULL);

        hProgressBar = CreateWindowExW(0, PROGRESS_CLASSW, NULL, WS_CHILD | WS_VISIBLE, 36, 318, 290, 22, hwnd, (HMENU)ID_PROGRESS, NULL, NULL);
        SendMessageW(hProgressBar, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
        hBtnStop = CreateWindowW(L"BUTTON", L"Durdur", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, 336, 316, 112, 26, hwnd, (HMENU)ID_BTN_STOPSCAN, NULL, NULL);
        EnableWindow(hBtnStop, FALSE);

        // --- Panel: Bellek Yazma — pointer zinciri + hex görüntüleyici + NOP aracı ---
        CreateWindowW(L"STATIC", L"Adres (Hex):", WS_VISIBLE | WS_CHILD, 36, 438, 90, 20, hwnd, NULL, NULL, NULL);
        // Adres geçmişi için düzenlenebilir COMBOBOX
        hEditAddr = CreateWindowW(L"COMBOBOX", L"", WS_VISIBLE | WS_CHILD | CBS_DROPDOWN | CBS_AUTOHSCROLL | WS_VSCROLL, 132, 434, 130, 200, hwnd, (HMENU)ID_EDIT_ADDR, NULL, NULL);

        CreateWindowW(L"STATIC", L"Yeni Değer:", WS_VISIBLE | WS_CHILD, 276, 438, 80, 20, hwnd, NULL, NULL, NULL);
        hEditNewVal = CreateWindowW(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER, 362, 434, 82, 26, hwnd, (HMENU)ID_EDIT_NEWVAL, NULL, NULL);

        CreateWindowW(L"BUTTON", L"Değeri Değiştir (Write)", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, 36, 468, 488, 34, hwnd, (HMENU)ID_BTN_WRITE, NULL, NULL);

        CreateWindowW(L"STATIC", L"Açıklama:", WS_VISIBLE | WS_CHILD, 36, 516, 70, 20, hwnd, NULL, NULL, NULL);
        hEditDesc = CreateWindowW(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER, 112, 512, 200, 26, hwnd, (HMENU)ID_EDIT_DESC, NULL, NULL);
        CreateWindowW(L"BUTTON", L"Listeye Ekle", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, 324, 511, 120, 28, hwnd, (HMENU)ID_BTN_ADDLIST, NULL, NULL);

        // Çoklu seviyeli pointer zinciri girişi: "14,2C,8" gibi virgülle ayrılmış hex offsetler
        CreateWindowW(L"STATIC", L"Ofset Zinciri (hex,virgül):", WS_VISIBLE | WS_CHILD, 36, 550, 160, 18, hwnd, NULL, NULL, NULL);
        hEditChainOff = CreateWindowW(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER, 200, 546, 110, 24, hwnd, (HMENU)ID_EDIT_CHAINOFF, NULL, NULL);
        CreateWindowW(L"STATIC", L"Max Sv:", WS_VISIBLE | WS_CHILD, 318, 550, 50, 18, hwnd, NULL, NULL, NULL);
        hEditMaxLevel = CreateWindowW(L"EDIT", L"2", WS_VISIBLE | WS_CHILD | WS_BORDER, 372, 546, 36, 24, hwnd, (HMENU)ID_EDIT_MAXLEVEL, NULL, NULL);
        CreateWindowW(L"BUTTON", L"Zincir Ekle", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, 36, 580, 130, 28, hwnd, (HMENU)ID_BTN_ADDCHAIN, NULL, NULL);
        hBtnPointer = CreateWindowW(L"BUTTON", L"Pointer Tarama", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, 176, 580, 348, 28, hwnd, (HMENU)ID_BTN_POINTERSCAN, NULL, NULL);

        CreateWindowW(L"BUTTON", L"Hex Görüntüleyici", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, 36, 618, 239, 32, hwnd, (HMENU)ID_BTN_HEXVIEW, NULL, NULL);
        CreateWindowW(L"BUTTON", L"Disassembler / NOP", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, 286, 618, 238, 32, hwnd, (HMENU)ID_BTN_NOPTOOL, NULL, NULL);

        CreateWindowW(L"STATIC", L"Dondurma Hızı (ms):", WS_VISIBLE | WS_CHILD, 36, 664, 170, 18, hwnd, NULL, NULL, NULL);
        hEditFreezeMs = CreateWindowW(L"EDIT", L"150", WS_VISIBLE | WS_CHILD | WS_BORDER, 214, 660, 60, 24, hwnd, (HMENU)ID_EDIT_FREEZEMS, NULL, NULL);
        CreateWindowW(L"BUTTON", L"Uygula", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, 286, 658, 90, 28, hwnd, (HMENU)ID_BTN_APPLYFREEZE, NULL, NULL);

        // --- Panel: Log — yükseklik pencereyle birlikte esner (bkz. RelayoutMainWindow) ---
        hLogBox = CreateWindowW(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL | ES_READONLY, 36, 782, 488, 96, hwnd, (HMENU)ID_LOG_BOX, NULL, NULL);

        // --- Panel: Sonuçlar — genişlik pencereyle birlikte esner (bkz. RelayoutMainWindow) ---
        CreateWindowW(L"STATIC", L"Filtre:", WS_VISIBLE | WS_CHILD, 576, 62, 50, 20, hwnd, NULL, NULL, NULL);
        hEditFilter = CreateWindowW(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER, 632, 58, 260, 26, hwnd, (HMENU)ID_EDIT_FILTER, NULL, NULL);
        hBtnFilter = CreateWindowW(L"BUTTON", L"Filtrele", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, 906, 57, 100, 28, hwnd, (HMENU)ID_BTN_FILTER, NULL, NULL);
        hListRes = CreateWindowW(L"LISTBOX", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | LBS_NOTIFY | WS_VSCROLL, 576, 100, 430, 222, hwnd, (HMENU)ID_LIST_RES, NULL, NULL);

        // --- Panel: Kayıtlı Adresler / Cheat Tablosu — genişlik+yükseklik pencereyle birlikte esner ---
        hListSaved = CreateWindowW(L"LISTBOX", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | LBS_NOTIFY | LBS_OWNERDRAWFIXED | LBS_HASSTRINGS | WS_VSCROLL, 576, 394, 430, 404, hwnd, (HMENU)ID_LIST_SAVED, NULL, NULL);
        hBtnDelList = CreateWindowW(L"BUTTON", L"Sil", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, 576, 808, 100, 30, hwnd, (HMENU)ID_BTN_DELLIST, NULL, NULL);
        hBtnSaveTable = CreateWindowW(L"BUTTON", L"Kaydet", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, 686, 808, 100, 30, hwnd, (HMENU)ID_BTN_SAVETABLE, NULL, NULL);
        hBtnLoadTable = CreateWindowW(L"BUTTON", L"Yükle", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, 796, 808, 100, 30, hwnd, (HMENU)ID_BTN_LOADTABLE, NULL, NULL);
        hBtnClearFilter = CreateWindowW(L"BUTTON", L"Filtre Temizle", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, 906, 808, 100, 30, hwnd, (HMENU)ID_BTN_CLEARFILTER, NULL, NULL);

        EnumChildWindows(hwnd, ApplyFontProc, (LPARAM)hFont);

        g_oldSavedListProc = (WNDPROC)SetWindowLongPtrW(hListSaved, GWLP_WNDPROC, (LONG_PTR)SavedListSubclassProc);

        SetTimer(hwnd, TIMER_FREEZE, g_freezeIntervalMs, NULL);
        EnableDarkTitleBar(hwnd);
        RelayoutMainWindow(hwnd); // pencere ilk açıldığındaki gerçek istemci boyutuna göre panelleri hizala

        LogMessage(L"[+] C++ Cheat Engine (All Type Supported) Başlatıldı.");
        LogMessage(L"[i] Kısayollar: F2 = First Scan, F3 = Next Scan.");
        break;

    case WM_MEASUREITEM: {
        LPMEASUREITEMSTRUCT mis = (LPMEASUREITEMSTRUCT)lParam;
        if (mis->CtlID == ID_LIST_SAVED) mis->itemHeight = 20;
        break;
    }

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        for (const auto& panel : g_mainPanels) {
            DrawCardPanel(hdc, panel);
        }
        EndPaint(hwnd, &ps);
        break;
    }

    case WM_ERASEBKGND: {
        // Zemini burada dolduruyoruz ki WM_PAINT sırasında kartlar üstüne
        // çizilirken gereksiz bir ikinci dolgu/titreşim olmasın.
        HDC hdc = (HDC)wParam;
        RECT rc; GetClientRect(hwnd, &rc);
        FillRect(hdc, &rc, hBrushBg);
        return 1;
    }

    case WM_GETMINMAXINFO: {
        // Pencere büyütülebilir/"Ekranı Kapla" (maximize) yapılabilir, ancak
        // panellerin üst üste binmemesi için başlangıç boyutundan küçültülemez.
        LPMINMAXINFO mmi = (LPMINMAXINFO)lParam;
        mmi->ptMinTrackSize.x = MAIN_WIN_MIN_W;
        mmi->ptMinTrackSize.y = MAIN_WIN_MIN_H;
        break;
    }

    case WM_SIZE: {
        if (wParam != SIZE_MINIMIZED) {
            RelayoutMainWindow(hwnd);
        }
        break;
    }

    case WM_TIMER:
        if (wParam == TIMER_FREEZE) {
            for (auto& e : savedEntries) {
                if (e.frozen) {
                    uintptr_t addr = ResolveEntryAddress(e);
                    if (addr != 0) WriteMemory(addr, e.type, e.frozenValue, true);
                }
            }
        }
        break;

    case WM_COMMAND:
        if (LOWORD(wParam) == ID_BTN_CONNECT) {
            wchar_t nameBuf[128];
            GetWindowTextW(hEditName, nameBuf, 128);
            if (wcslen(nameBuf) > 0) {
                DWORD pid = GetProcessIdByName(nameBuf);
                if (pid == 0) pid = _wtoi(nameBuf);
                if (pid > 0) {
                    if (hProcess) CloseHandle(hProcess);
                    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
                    if (hProcess) {
                        wstringstream ss;
                        ss << L"[+] Bağlanıldı! PID: " << pid;
                        LogMessage(ss.str());

                        BOOL isWow64 = FALSE;
                        IsWow64Process(hProcess, &isWow64);
#ifdef _WIN64
                        if (isWow64) LogMessage(L"[!] UYARI: Hedef süreç 32-bit (WOW64) görünüyor, bu araç 64-bit. Bazı sonuçlar hatalı olabilir.");
#else
                        if (!isWow64) LogMessage(L"[!] UYARI: Bu araç 32-bit derlenmiş; hedef 64-bit bir süreç olabilir.");
#endif
                    } else {
                        LogMessage(L"[-] Erişim reddedildi (Yönetici olarak çalıştırın).");
                    }
                } else {
                    LogMessage(L"[-] Süreç bulunamadı!");
                }
            }
        }
        else if (LOWORD(wParam) == ID_BTN_PROCLIST) {
            if (!hProcListDlg) {
                WNDCLASSW wc = {};
                wc.lpfnWndProc = ProcListWndProc;
                wc.hInstance = GetModuleHandle(NULL);
                wc.lpszClassName = L"ProcessListWindowClass";
                wc.hCursor = LoadCursor(NULL, IDC_ARROW);
                wc.hbrBackground = hBrushBg;
                RegisterClassW(&wc);

                hProcListDlg = CreateWindowExW(0, L"ProcessListWindowClass", L"Process List",
                    WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
                    CW_USEDEFAULT, CW_USEDEFAULT, 400, 390,
                    hwnd, NULL, GetModuleHandle(NULL), NULL);
                ShowWindow(hProcListDlg, SW_SHOW);
            } else {
                SetForegroundWindow(hProcListDlg);
            }
        }
        else if (LOWORD(wParam) == ID_BTN_FIRST || LOWORD(wParam) == ID_BTN_NEXT) {
            if (g_scanning.load()) {
                LogMessage(L"[-] Zaten bir tarama çalışıyor. Lütfen bekleyin veya durdurun.");
            } else if (!hProcess) {
                LogMessage(L"[-] Önce bir sürece bağlanmalısınız!");
            } else {
                wchar_t valBuf[64], valBuf2[64];
                GetWindowTextW(hEditVal, valBuf, 64);
                GetWindowTextW(hEditVal2, valBuf2, 64);

                int valTypeIdx = (int)SendMessageW(hComboValType, CB_GETCURSEL, 0, 0);
                ValueType vType = (ValueType)valTypeIdx;
                int scanType = (int)SendMessageW(hComboScanType, CB_GETCURSEL, 0, 0);

                double t1 = 0, t2 = 0;
                if (wcslen(valBuf) > 0) t1 = _wtof(valBuf);
                if (wcslen(valBuf2) > 0) t2 = _wtof(valBuf2);

                ScanParams* params = new ScanParams();
                params->t1 = t1; params->t2 = t2; params->vType = vType; params->scanType = scanType;
                if (vType == TYPE_AOB) params->aobPattern = valBuf;
                bool isFirst = (LOWORD(wParam) == ID_BTN_FIRST);
                if (isFirst && hComboRegion) {
                    params->regionFilter = (int)SendMessageW(hComboRegion, CB_GETCURSEL, 0, 0);
                    if (params->regionFilter < 0) params->regionFilter = REGION_ALL;
                }

                if (wcslen(valBuf) > 0) AddToHistory(hEditVal, g_valHistory, valBuf);

                if (!isFirst) params->baseResults = results; // ana thread'de anlık kopya alınır (yarış durumu yok)

                g_scanCancel = false;
                g_scanning = true;
                EnableWindow(hBtnFirst, FALSE);
                EnableWindow(hBtnNext, FALSE);
                EnableWindow(hBtnStop, TRUE);
                SendMessageW(hProgressBar, PBM_SETPOS, 0, 0);

                HANDLE hThread = CreateThread(NULL, 0, isFirst ? FirstScanThread : NextScanThread, params, 0, NULL);
                if (hThread) {
                    CloseHandle(hThread);
                } else {
                    LogMessage(L"[-] Tarama başlatılamadı.");
                    delete params;
                    g_scanning = false;
                    EnableWindow(hBtnFirst, TRUE);
                    EnableWindow(hBtnNext, TRUE);
                    EnableWindow(hBtnStop, FALSE);
                }
            }
        }
        else if (LOWORD(wParam) == ID_BTN_STOPSCAN) {
            if (g_scanning.load()) {
                g_scanCancel = true;
                LogMessage(L"[*] Durdurma istendi...");
            }
        }
        else if (LOWORD(wParam) == ID_BTN_POINTERSCAN) {
            if (g_scanning.load()) {
                LogMessage(L"[-] Zaten bir işlem çalışıyor.");
            } else if (!hProcess) {
                LogMessage(L"[-] Önce bir sürece bağlanmalısınız!");
            } else {
                wchar_t addrBuf[32];
                GetWindowTextW(hEditAddr, addrBuf, 32);
                uintptr_t target = 0;
                wistringstream(addrBuf) >> hex >> target;

                if (target == 0) {
                    LogMessage(L"[-] Pointer taraması için Adres kutusuna geçerli bir hedef adres girin.");
                } else {
                    wchar_t lvlBuf[16];
                    GetWindowTextW(hEditMaxLevel, lvlBuf, 16);
                    int maxLevel = _wtoi(lvlBuf);
                    if (maxLevel < 1) maxLevel = 1;
                    if (maxLevel > 3) maxLevel = 3;

                    PointerScanParams* pp = new PointerScanParams{ target, maxLevel };
                    g_scanCancel = false;
                    g_scanning = true;
                    EnableWindow(hBtnFirst, FALSE);
                    EnableWindow(hBtnNext, FALSE);
                    EnableWindow(hBtnStop, TRUE);
                    SendMessageW(hProgressBar, PBM_SETPOS, 0, 0);
                    wstringstream lss;
                    lss << L"[*] Pointer taraması başlatıldı (ana modül, " << maxLevel << L" seviyeye kadar)...";
                    LogMessage(lss.str());

                    HANDLE hThread = CreateThread(NULL, 0, PointerScanThread, pp, 0, NULL);
                    if (hThread) {
                        CloseHandle(hThread);
                    } else {
                        delete pp;
                        g_scanning = false;
                        EnableWindow(hBtnFirst, TRUE);
                        EnableWindow(hBtnNext, TRUE);
                        EnableWindow(hBtnStop, FALSE);
                    }
                }
            }
        }
        else if (LOWORD(wParam) == ID_BTN_WRITE) {
            wchar_t addrBuf[32], valBuf[32];
            GetWindowTextW(hEditAddr, addrBuf, 32);
            GetWindowTextW(hEditNewVal, valBuf, 32);

            uintptr_t addr = 0;
            wistringstream(addrBuf) >> hex >> addr;

            int valTypeIdx = (int)SendMessageW(hComboValType, CB_GETCURSEL, 0, 0);
            ValueType vType = (ValueType)valTypeIdx;
            if (vType == TYPE_ALL || vType == TYPE_AOB) vType = TYPE_4BYTES; // All/AOB seçiliyse yazma için varsayılan 4 Bytes al

            WriteMemory(addr, vType, valBuf);
            AddToHistory(hEditAddr, g_addrHistory, addrBuf);
        }
        else if (LOWORD(wParam) == ID_BTN_ADDCHAIN) {
            // Manuel çoklu seviyeli pointer zinciri ekleme: Adres kutusu ana modüle göre
            // ilk (statik) offset, "Ofset Zinciri" kutusu ek seviyeleri temsil eder.
            if (!hProcess) {
                LogMessage(L"[-] Önce bir sürece bağlanmalısınız!");
            } else {
                wchar_t addrBuf[32], chainBuf[256], descBuf[128];
                GetWindowTextW(hEditAddr, addrBuf, 32);
                GetWindowTextW(hEditChainOff, chainBuf, 256);
                GetWindowTextW(hEditDesc, descBuf, 128);

                uintptr_t off0 = 0;
                wistringstream(addrBuf) >> hex >> off0;

                vector<uintptr_t> chain;
                chain.push_back(off0);
                wstringstream chainSS(chainBuf);
                wstring tok;
                while (getline(chainSS, tok, L',')) {
                    // baştaki/sondaki boşlukları at
                    size_t a = tok.find_first_not_of(L" \t");
                    size_t b = tok.find_last_not_of(L" \t");
                    if (a == wstring::npos) continue;
                    tok = tok.substr(a, b - a + 1);
                    if (tok.empty()) continue;
                    uintptr_t v = 0;
                    wistringstream(tok) >> hex >> v;
                    chain.push_back(v);
                }

                HMODULE mods[1];
                DWORD needed = 0;
                wchar_t modName[MAX_PATH] = L"";
                if (K32EnumProcessModules(hProcess, mods, sizeof(mods), &needed) && needed >= sizeof(HMODULE)) {
                    K32GetModuleBaseNameW(hProcess, mods[0], modName, MAX_PATH);
                }

                int valTypeIdx = (int)SendMessageW(hComboValType, CB_GETCURSEL, 0, 0);
                ValueType vType = (ValueType)valTypeIdx;
                if (vType == TYPE_ALL || vType == TYPE_AOB) vType = TYPE_4BYTES;

                SavedEntry e;
                e.isPointer = true;
                e.moduleName = modName;
                e.chainOffsets = chain;
                e.type = vType;
                e.description = wstring(descBuf);
                if (e.description.empty()) e.description = L"(pointer zinciri)";
                e.frozen = false;

                uintptr_t resolved = ResolveEntryAddress(e);
                e.frozenValue = FormatMemoryValue(resolved, vType);
                savedEntries.push_back(e);
                RefreshSavedList();

                wstringstream ss;
                ss << L"[+] Pointer zinciri eklendi: " << e.description << L" (" << chain.size() << L" seviye)";
                LogMessage(ss.str());
            }
        }
        else if (LOWORD(wParam) == ID_BTN_APPLYFREEZE) {
            wchar_t buf[16];
            GetWindowTextW(hEditFreezeMs, buf, 16);
            int ms = _wtoi(buf);
            if (ms < 10) ms = 10;
            if (ms > 10000) ms = 10000;
            g_freezeIntervalMs = ms;
            KillTimer(hwnd, TIMER_FREEZE);
            SetTimer(hwnd, TIMER_FREEZE, g_freezeIntervalMs, NULL);
            wstringstream ss;
            ss << L"[+] Dondurma yazma hızı " << ms << L" ms olarak ayarlandı.";
            LogMessage(ss.str());
        }
        else if (LOWORD(wParam) == ID_BTN_FILTER) {
            wchar_t buf[256];
            GetWindowTextW(hEditFilter, buf, 256);
            g_resultFilter = buf;
            RefreshResultsListFiltered();
        }
        else if (LOWORD(wParam) == ID_BTN_CLEARFILTER) {
            g_resultFilter.clear();
            SetWindowTextW(hEditFilter, L"");
            RefreshResultsListFiltered();
        }
        else if (LOWORD(wParam) == ID_BTN_HEXVIEW || LOWORD(wParam) == ID_BTN_NOPTOOL) {
            if (!hProcess) {
                LogMessage(L"[-] Önce bir sürece bağlanmalısınız!");
            } else {
                wchar_t addrBuf[32];
                GetWindowTextW(hEditAddr, addrBuf, 32);
                uintptr_t addr = 0;
                wistringstream(addrBuf) >> hex >> addr;
                OpenHexViewer(hwnd, addr);
            }
        }
        else if (LOWORD(wParam) == ID_BTN_ADDLIST) {
            wchar_t addrBuf[32], descBuf[128];
            GetWindowTextW(hEditAddr, addrBuf, 32);
            GetWindowTextW(hEditDesc, descBuf, 128);
            uintptr_t addr = 0;
            wistringstream(addrBuf) >> hex >> addr;

            if (addr == 0) {
                LogMessage(L"[-] Geçerli bir adres girin.");
            } else {
                int valTypeIdx = (int)SendMessageW(hComboValType, CB_GETCURSEL, 0, 0);
                ValueType vType = (ValueType)valTypeIdx;
                if (vType == TYPE_ALL || vType == TYPE_AOB) vType = TYPE_4BYTES;

                SavedEntry e;
                e.isPointer = false;
                e.address = addr;
                e.type = vType;
                e.description = wstring(descBuf);
                if (e.description.empty()) e.description = L"(açıklama yok)";
                e.frozen = false;
                e.frozenValue = FormatMemoryValue(addr, vType);
                savedEntries.push_back(e);
                RefreshSavedList();
                LogMessage(L"[+] Listeye eklendi: " + e.description);
                AddToHistory(hEditAddr, g_addrHistory, addrBuf);
            }
        }
        else if (LOWORD(wParam) == ID_BTN_DELLIST) {
            int sel = (int)SendMessageW(hListSaved, LB_GETCURSEL, 0, 0);
            if (sel != LB_ERR && sel < (int)savedEntries.size()) {
                savedEntries.erase(savedEntries.begin() + sel);
                RefreshSavedList();
            }
        }
        else if (LOWORD(wParam) == ID_BTN_SAVETABLE) {
            SaveCheatTable(hwnd);
        }
        else if (LOWORD(wParam) == ID_BTN_LOADTABLE) {
            LoadCheatTable(hwnd);
        }
        else if (LOWORD(wParam) == ID_MENU_COPYADDR) {
            uintptr_t addr = 0;
            if (g_ctxMenuList == hListRes && g_ctxMenuIndex >= 0 && g_ctxMenuIndex < (int)results.size()) {
                addr = results[g_ctxMenuIndex].address;
            } else if (g_ctxMenuList == hListSaved && g_ctxMenuIndex >= 0 && g_ctxMenuIndex < (int)savedEntries.size()) {
                addr = ResolveEntryAddress(savedEntries[g_ctxMenuIndex]);
            }

            if (addr != 0) {
                wstringstream ss;
                ss << L"0x" << uppercase << hex << addr;
                wstring text = ss.str();
                if (OpenClipboard(hwnd)) {
                    EmptyClipboard();
                    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, (text.size() + 1) * sizeof(wchar_t));
                    if (hMem) {
                        wchar_t* dst = (wchar_t*)GlobalLock(hMem);
                        wcscpy(dst, text.c_str());
                        GlobalUnlock(hMem);
                        SetClipboardData(CF_UNICODETEXT, hMem);
                    }
                    CloseClipboard();
                    LogMessage(L"[+] Adres panoya kopyalandı: " + text);
                }
            }
        }
        else if (HIWORD(wParam) == LBN_DBLCLK && LOWORD(wParam) == ID_LIST_RES) {
            int sel = (int)SendMessageW(hListRes, LB_GETCURSEL, 0, 0);
            if (sel != LB_ERR && sel < (int)results.size()) {
                wstringstream ss;
                ss << uppercase << hex << results[sel].address;
                SetWindowTextW(hEditAddr, ss.str().c_str());

                wstring label = PromptTextInput(hwnd, L"Adresi Etiketle", L"Bu adres için bir isim girin (örn: Player HP):", L"");
                if (!label.empty()) {
                    SavedEntry e;
                    e.isPointer = false;
                    e.address = results[sel].address;
                    e.type = results[sel].type;
                    e.description = label;
                    e.frozen = false;
                    e.frozenValue = FormatMemoryValue(e.address, e.type);
                    savedEntries.push_back(e);
                    RefreshSavedList();
                    LogMessage(L"[+] Cheat tablosuna eklendi: " + label);
                }
            }
        }
        else if (HIWORD(wParam) == LBN_DBLCLK && LOWORD(wParam) == ID_LIST_SAVED) {
            int sel = (int)SendMessageW(hListSaved, LB_GETCURSEL, 0, 0);
            if (sel != LB_ERR && sel < (int)savedEntries.size()) {
                uintptr_t addr = ResolveEntryAddress(savedEntries[sel]);
                wstringstream ss;
                ss << uppercase << hex << addr;
                SetWindowTextW(hEditAddr, ss.str().c_str());
            }
        }
        break;

    case WM_CONTEXTMENU: {
        HWND hCtl = (HWND)wParam;
        if (hCtl == hListRes || hCtl == hListSaved) {
            int xScreen = (short)(lParam & 0xFFFF);
            int yScreen = (short)((lParam >> 16) & 0xFFFF);
            POINT ptClient = { xScreen, yScreen };
            ScreenToClient(hCtl, &ptClient);
            LRESULT hit = SendMessageW(hCtl, LB_ITEMFROMPOINT, 0, MAKELPARAM(ptClient.x, ptClient.y));
            BOOL outside = HIWORD(hit);
            int index = LOWORD(hit);
            if (!outside) {
                SendMessageW(hCtl, LB_SETCURSEL, index, 0);
                g_ctxMenuList = hCtl;
                g_ctxMenuIndex = index;

                HMENU hMenu = CreatePopupMenu();
                AppendMenuW(hMenu, MF_STRING, ID_MENU_COPYADDR, L"Adresi Kopyala");
                TrackPopupMenu(hMenu, TPM_RIGHTBUTTON, xScreen, yScreen, 0, hwnd, NULL);
                DestroyMenu(hMenu);
            }
        }
        break;
    }

    case WM_APP_PROGRESS:
        SendMessageW(hProgressBar, PBM_SETPOS, (WPARAM)wParam, 0);
        break;

    case WM_APP_SCANDONE: {
        vector<MemoryResult>* out = (vector<MemoryResult>*)wParam;
        bool wasCancelled = g_scanCancel.load();
        results = std::move(*out);
        delete out;

        RefreshResultsListFiltered();

        wstringstream ss;
        ss << (wasCancelled ? L"[!] Tarama durduruldu. " : L"[+] Tarama tamamlandı. ") << L"Bulunan: " << results.size();
        LogMessage(ss.str());

        g_scanning = false;
        g_scanCancel = false;
        EnableWindow(hBtnFirst, TRUE);
        EnableWindow(hBtnNext, TRUE);
        EnableWindow(hBtnStop, FALSE);
        SendMessageW(hProgressBar, PBM_SETPOS, 0, 0);
        break;
    }

    case WM_APP_POINTERDONE: {
        vector<SavedEntry>* pf = (vector<SavedEntry>*)wParam;
        size_t foundCount = pf->size();
        for (auto& e : *pf) savedEntries.push_back(e);
        delete pf;
        RefreshSavedList();

        wstringstream ss;
        ss << L"[+] Pointer taraması tamamlandı. Bulunan: " << foundCount;
        LogMessage(ss.str());

        g_scanning = false;
        g_scanCancel = false;
        EnableWindow(hBtnFirst, TRUE);
        EnableWindow(hBtnNext, TRUE);
        EnableWindow(hBtnStop, FALSE);
        SendMessageW(hProgressBar, PBM_SETPOS, 0, 0);
        break;
    }

    case WM_DRAWITEM: {
        LPDRAWITEMSTRUCT dis = (LPDRAWITEMSTRUCT)lParam;
        if (dis->CtlType == ODT_BUTTON) {
            DrawAccentButton(dis);
        } else if (dis->CtlType == ODT_LISTBOX && dis->CtlID == ID_LIST_SAVED) {
            DrawSavedListItem(dis);
        }
        break;
    }

    case WM_CTLCOLORSTATIC: {
        HDC hdc = (HDC)wParam;
        HWND hCtl = (HWND)lParam;
        wchar_t cls[32];
        GetClassNameW(hCtl, cls, 32);
        if (_wcsicmp(cls, L"Edit") == 0) {
            // Salt-okunur log kutusu
            SetBkMode(hdc, OPAQUE);
            SetBkColor(hdc, THEME_CARD_BG);
            SetTextColor(hdc, THEME_TEXT);
            return (LRESULT)hBrushWhite;
        }
        // Etiketler artık beyaz kart panellerinin üzerinde durduğu için
        // arkaplanları da beyaza eşleniyor (önceden gri pencere zeminiydi).
        SetBkMode(hdc, OPAQUE);
        SetBkColor(hdc, THEME_CARD_BG);
        SetTextColor(hdc, THEME_TEXT);
        return (LRESULT)hBrushWhite;
    }
    case WM_CTLCOLOREDIT: {
        HDC hdc = (HDC)wParam;
        SetBkColor(hdc, THEME_CARD_BG);
        SetTextColor(hdc, THEME_TEXT);
        return (LRESULT)hBrushWhite;
    }
    case WM_CTLCOLORLISTBOX: {
        HDC hdc = (HDC)wParam;
        SetBkColor(hdc, THEME_CARD_BG);
        SetTextColor(hdc, THEME_TEXT);
        return (LRESULT)hBrushWhite;
    }

    case WM_DESTROY:
        KillTimer(hwnd, TIMER_FREEZE);
        if (hProcess) CloseHandle(hProcess);
        PostQuitMessage(0);
        break;

    default:
        return DefWindowProcW(hwnd, uMsg, wParam, lParam);
    }
    return 0;
}

int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow);

extern "C" int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    return wWinMain(hInstance, hPrevInstance, GetCommandLineW(), nCmdShow);
}

int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow) {
    const wchar_t CLASS_NAME[] = L"CheatEngineLiteAllType";

    INITCOMMONCONTROLSEX icc;
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_PROGRESS_CLASS;
    InitCommonControlsEx(&icc);

    // Tema kaynakları (fontlar + fırçalar)
    hFont = CreateFontW(-15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
    hFontBold = CreateFontW(-15, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
    hBrushBg = CreateSolidBrush(THEME_WINDOW_BG);
    hBrushWhite = CreateSolidBrush(THEME_CARD_BG);

    WNDCLASSW wc = {};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = hBrushBg;
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);

    RegisterClassW(&wc);

    HWND hwnd = CreateWindowExW(
        0, CLASS_NAME, L"HexaCore | Bellek tarama/düzenleme aracı",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_MAXIMIZEBOX | WS_THICKFRAME,
        CW_USEDEFAULT, CW_USEDEFAULT, MAIN_WIN_MIN_W, MAIN_WIN_MIN_H,
        NULL, NULL, hInstance, NULL
    );

    HACCEL hAccel = NULL;
    {
        ACCEL accels[2];
        accels[0].fVirt = FVIRTKEY; accels[0].key = VK_F2; accels[0].cmd = ID_BTN_FIRST;
        accels[1].fVirt = FVIRTKEY; accels[1].key = VK_F3; accels[1].cmd = ID_BTN_NEXT;
        hAccel = CreateAcceleratorTable(accels, 2);
    }

    if (!hwnd) return 0;
    g_hMainWnd = hwnd;

    ShowWindow(hwnd, nCmdShow);

    MSG msg = {};
    while (GetMessageW(&msg, NULL, 0, 0)) {
        // F2 (First Scan) / F3 (Next Scan) kısayolları için hızlandırıcı tablosu
        if (!hAccel || !TranslateAcceleratorW(hwnd, hAccel, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }

    return 0;
}
