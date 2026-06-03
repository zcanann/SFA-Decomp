#include "ghidra_import.h"
#include "main/dll/baddie/Tumbleweed.h"
#include "main/dll/FRONT/dll_39.h"
#include "stdarg.h"

extern undefined4 FUN_80003494();
extern undefined4 FUN_80006728();
extern undefined4 FUN_800067bc();
extern undefined4 FUN_800067c0();
extern bool FUN_800067f0();
extern undefined4 FUN_80006810();
extern undefined8 FUN_80006824();
extern void* FUN_800069a8();
extern int FUN_800069c0();
extern undefined4 FUN_800069d4();
extern byte FUN_80006b20();
extern undefined4 FUN_80006b30();
extern int FUN_80006b7c();
extern undefined4 FUN_80006b84();
extern uint FUN_80006c00();
extern uint FUN_80006c10();
extern undefined4 FUN_80006c84();
extern undefined8 FUN_80006c88();
extern void* FUN_80006c9c();
extern void* FUN_80017470();
extern undefined4 FUN_80017478();
extern undefined4 FUN_8001747c();
extern undefined8 FUN_80017484();
extern int FUN_8001748c();
extern undefined8 FUN_80017494();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern double FUN_80017708();
extern double FUN_80017714();
extern int FUN_80017730();
extern int FUN_800178dc();
extern undefined4 FUN_800178e4();
extern undefined4 FUN_800178e8();
extern undefined4 FUN_80017964();
extern undefined4 FUN_80017a2c();
extern int FUN_80017a54();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined8 FUN_80017ac8();
extern undefined4 FUN_80017ae4();
extern int FUN_8002fc3c();
extern undefined4 FUN_800305f8();
extern uint ObjGroup_ContainsObject();
extern int ObjGroup_FindNearestObject();
extern void* ObjGroup_GetObjects();
extern undefined8 ObjLink_DetachChild();
extern undefined4 ObjLink_AttachChild();
extern undefined4 FUN_80039468();
extern undefined4 FUN_8003b1a4();
extern undefined4 FUN_8003b280();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_8003b878();
extern undefined4 FUN_8004812c();
extern undefined8 FUN_80053754();
extern undefined4 FUN_8005398c();
extern uint FUN_8005b024();
extern undefined4 FUN_8005d370();
extern uint FUN_8006f764();
extern undefined4 FUN_8006fd90();
extern undefined4 FUN_80070414();
extern undefined4 FUN_8007089c();
extern undefined4 FUN_800709d8();
extern undefined4 FUN_800709e0();
extern undefined4 FUN_800709e8();
extern undefined4 FUN_800713a4();
extern undefined4 FUN_80080f70();
extern undefined4 FUN_80080f7c();
extern undefined4 FUN_80080f80();
extern int FUN_801113c0();
extern undefined4 FUN_80117318();
extern undefined4 FUN_801184b8();
extern undefined4 FUN_80129fb0();
extern undefined4 FUN_80129ff8();
extern undefined4 FUN_8012c9e8();
extern undefined4 FUN_801302a4();
extern ushort FUN_8013041c();
extern undefined4 FUN_80131cc4();
extern double FUN_8014cbcc();
extern undefined4 FUN_80242114();
extern undefined4 FUN_802430ec();
extern undefined4 FUN_80243e74();
extern undefined4 FUN_80243e9c();
extern undefined4 FUN_80246a0c();
extern undefined4 FUN_80246dcc();
extern undefined8 FUN_802475b8();
extern undefined4 FUN_80247a48();
extern undefined4 FUN_8024c8cc();
extern undefined4 FUN_8024c910();
extern undefined8 FUN_8024d054();
extern undefined4 FUN_8024dcb8();
extern undefined4 FUN_8024ddd4();
extern undefined4 FUN_80256bc4();
extern undefined4 FUN_802570dc();
extern undefined4 FUN_80257b5c();
extern undefined8 FUN_80258a94();
extern undefined4 FUN_80259000();
extern undefined4 FUN_80259288();
extern undefined4 FUN_8025c428();
extern undefined4 FUN_8025d6ac();
extern undefined4 FUN_8025d80c();
extern undefined4 FUN_8025d888();
extern undefined4 FUN_8025da88();
extern int FUN_80286718();
extern undefined2 FUN_802867ac();
extern undefined4 FUN_802867f8();
extern ulonglong FUN_8028682c();
extern undefined8 FUN_80286830();
extern undefined8 FUN_80286834();
extern undefined8 FUN_80286838();
extern undefined8 FUN_8028683c();
extern short FUN_80286840();
extern undefined4 FUN_80286878();
extern undefined4 FUN_8028687c();
extern undefined4 FUN_80286880();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_8028fde8();
extern undefined4 FUN_8028fec8();
extern undefined4 sqrtf_8029312c();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern uint FUN_80294be4();
extern uint countLeadingZeros();

extern undefined4 DAT_8030eac0;
extern undefined4 DAT_8030eac4;
extern undefined4 DAT_8031d15c;
extern undefined4 DAT_8031d15e;
extern undefined4 DAT_8031d15f;
extern undefined4 DAT_8031d270;
extern undefined4 DAT_8031d300;
extern undefined4 DAT_8031d302;
extern undefined4 DAT_8031d304;
extern undefined4 DAT_8031d888;
extern undefined4 DAT_8031d88a;
extern undefined4 DAT_8031d8a0;
extern short DAT_8031da38;
extern undefined4 DAT_8031dae0;
extern undefined4 DAT_8031dae2;
extern undefined4 DAT_803974e0;
extern undefined4 DAT_803aaa30;
extern undefined4 DAT_803aab98;
extern int DAT_803aabf8;
extern undefined4 DAT_803aabfc;
extern undefined4 DAT_803aac00;
extern undefined4 DAT_803aac04;
extern undefined4 DAT_803aac08;
extern undefined4 DAT_803aac0c;
extern undefined4 DAT_803aac10;
extern undefined4 DAT_803aac14;
extern undefined4 DAT_803aac18;
extern undefined4 DAT_803aac38;
extern undefined4 DAT_803aac3c;
extern undefined4 DAT_803aac40;
extern undefined4 DAT_803aac44;
extern undefined4 DAT_803aac50;
extern undefined4 DAT_803aac60;
extern undefined DAT_803aac78;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dc071;
extern undefined4 DAT_803dc6d6;
extern undefined4 DAT_803dc818;
extern undefined4 DAT_803dc819;
extern undefined4 DAT_803dc828;
extern undefined4 DAT_803dc82c;
extern undefined4 DAT_803dc830;
extern undefined4 DAT_803dc838;
extern undefined4 DAT_803dc83a;
extern undefined4 DAT_803dc850;
extern undefined4 DAT_803dc858;
extern undefined4 DAT_803dc860;
extern undefined4 DAT_803dc864;
extern undefined4 DAT_803dc868;
extern undefined4 DAT_803dc86c;
extern undefined4 DAT_803dc870;
extern undefined4 DAT_803dc871;
extern undefined4 DAT_803dc872;
extern undefined4 DAT_803dc878;
extern undefined* DAT_803dc87c;
extern undefined4 DAT_803dc880;
extern undefined4 DAT_803dc884;
extern undefined4 DAT_803dc888;
extern undefined4 DAT_803dc890;
extern undefined4 DAT_803dc898;
extern undefined4 DAT_803dd5e8;
extern undefined4* DAT_803dd6d0;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6e8;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd720;
extern undefined4* DAT_803dd72c;
extern undefined4* DAT_803dd738;
extern undefined4 DAT_803dd968;
extern undefined4 DAT_803dd96c;
extern undefined4 DAT_803de3db;
extern undefined4 DAT_803de400;
extern undefined4 DAT_803de422;
extern undefined4 DAT_803de43a;
extern undefined4 DAT_803de5a8;
extern undefined4 DAT_803de5a9;
extern undefined4 DAT_803de5aa;
extern undefined4 DAT_803de5ac;
extern undefined4 DAT_803de5b0;
extern undefined4 DAT_803de5b2;
extern undefined4 DAT_803de5b4;
extern undefined4 DAT_803de5b8;
extern undefined4 DAT_803de5bc;
extern undefined4 DAT_803de5c0;
extern undefined4 DAT_803de5c4;
extern undefined4 DAT_803de5c5;
extern undefined4 DAT_803de5c6;
extern undefined4 DAT_803de5c7;
extern undefined4 DAT_803de5c8;
extern undefined4 DAT_803de5ca;
extern undefined4 DAT_803de5dc;
extern undefined4 DAT_803de5e0;
extern undefined4 DAT_803de5ec;
extern undefined4 DAT_803de5f0;
extern undefined4 DAT_803de5f4;
extern undefined4 DAT_803de5f8;
extern undefined4 DAT_803de600;
extern undefined4 DAT_803de604;
extern undefined4 DAT_803de608;
extern undefined4 DAT_803de610;
extern undefined4 DAT_803de611;
extern undefined4 DAT_803de612;
extern undefined4 DAT_803de613;
extern undefined4 DAT_803de614;
extern undefined4 DAT_803de616;
extern undefined4 DAT_803de618;
extern undefined4 DAT_803de620;
extern undefined4 DAT_803de624;
extern undefined4 DAT_803de628;
extern undefined4 DAT_803de62a;
extern undefined4 DAT_803de62b;
extern undefined4 DAT_803de62c;
extern undefined4 DAT_803de638;
extern undefined4 DAT_803de63c;
extern undefined4 DAT_803de640;
extern undefined4 DAT_803de654;
extern undefined4 DAT_803de660;
extern undefined4 DAT_803de661;
extern undefined4 DAT_803de664;
extern undefined4 DAT_803de670;
extern undefined4 DAT_803de671;
extern undefined4 DAT_803de672;
extern undefined4 DAT_803de673;
extern undefined4 DAT_803de674;
extern undefined4 DAT_803de676;
extern undefined4 DAT_803de678;
extern undefined4 DAT_803de67c;
extern undefined4 DAT_803de680;
extern undefined4 DAT_803de684;
extern undefined4 DAT_803de688;
extern undefined4 DAT_803de68c;
extern undefined4 DAT_803de690;
extern undefined4 DAT_803de694;
extern undefined4 DAT_803de696;
extern undefined4 DAT_803de698;
extern undefined4 DAT_803de69a;
extern undefined4 DAT_803de69c;
extern undefined4 DAT_803de6a0;
extern undefined4 DAT_803de6a4;
extern undefined4 DAT_803de6a8;
extern undefined4 DAT_803de6ac;
extern undefined4 DAT_803de6b0;
extern undefined4 DAT_803de6b4;
extern undefined4 DAT_803de6b8;
extern undefined4 DAT_803de6bc;
extern undefined4 DAT_803de6c0;
extern undefined4 DAT_803e2e90;
extern undefined4 DAT_803e2e94;
extern undefined4 DAT_cc008000;
extern f64 DOUBLE_803e2ee0;
extern f64 DOUBLE_803e2ee8;
extern f64 DOUBLE_803e2f50;
extern f64 DOUBLE_803e2f58;
extern f64 DOUBLE_803e2f60;
extern f64 DOUBLE_803e2f78;
extern f64 DOUBLE_803e2f98;
extern f64 DOUBLE_803e2fa0;
extern f64 DOUBLE_803e3038;
extern f64 DOUBLE_803e3040;
extern f64 DOUBLE_803e3090;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dc81c;
extern f32 FLOAT_803dc820;
extern f32 FLOAT_803dc824;
extern f32 FLOAT_803dc83c;
extern f32 FLOAT_803dc840;
extern f32 FLOAT_803dc844;
extern f32 FLOAT_803dc848;
extern f32 FLOAT_803dc84c;
extern f32 FLOAT_803dc854;
extern f32 FLOAT_803dc874;
extern f32 FLOAT_803de5cc;
extern f32 FLOAT_803de5d0;
extern f32 FLOAT_803de5d4;
extern f32 FLOAT_803de5d8;
extern f32 FLOAT_803de5e8;
extern f32 FLOAT_803de5fc;
extern f32 FLOAT_803de61c;
extern f32 FLOAT_803de630;
extern f32 FLOAT_803de634;
extern f32 FLOAT_803de644;
extern f32 FLOAT_803de648;
extern f32 FLOAT_803de64c;
extern f32 FLOAT_803de650;
extern f32 FLOAT_803de658;
extern f32 FLOAT_803de65c;
extern f32 FLOAT_803de668;
extern f32 FLOAT_803de66c;
extern f32 FLOAT_803e2e98;
extern f32 FLOAT_803e2e9c;
extern f32 FLOAT_803e2ea0;
extern f32 FLOAT_803e2ea4;
extern f32 FLOAT_803e2ea8;
extern f32 FLOAT_803e2eac;
extern f32 FLOAT_803e2eb4;
extern f32 FLOAT_803e2eb8;
extern f32 FLOAT_803e2ebc;
extern f32 FLOAT_803e2ec0;
extern f32 FLOAT_803e2ec4;
extern f32 FLOAT_803e2ec8;
extern f32 FLOAT_803e2ecc;
extern f32 FLOAT_803e2ed0;
extern f32 FLOAT_803e2ed4;
extern f32 FLOAT_803e2ed8;
extern f32 FLOAT_803e2edc;
extern f32 FLOAT_803e2ef0;
extern f32 FLOAT_803e2ef4;
extern f32 FLOAT_803e2ef8;
extern f32 FLOAT_803e2efc;
extern f32 FLOAT_803e2f08;
extern f32 FLOAT_803e2f0c;
extern f32 FLOAT_803e2f10;
extern f32 FLOAT_803e2f14;
extern f32 FLOAT_803e2f18;
extern f32 FLOAT_803e2f1c;
extern f32 FLOAT_803e2f20;
extern f32 FLOAT_803e2f24;
extern f32 FLOAT_803e2f28;
extern f32 FLOAT_803e2f2c;
extern f32 FLOAT_803e2f30;
extern f32 FLOAT_803e2f38;
extern f32 FLOAT_803e2f3c;
extern f32 FLOAT_803e2f40;
extern f32 FLOAT_803e2f44;
extern f32 FLOAT_803e2f48;
extern f32 FLOAT_803e2f70;
extern f32 FLOAT_803e2f80;
extern f32 FLOAT_803e2f84;
extern f32 FLOAT_803e2f88;
extern f32 FLOAT_803e2f8c;
extern f32 FLOAT_803e2f90;
extern f32 FLOAT_803e2f94;
extern f32 FLOAT_803e2fa8;
extern f32 FLOAT_803e2fac;
extern f32 FLOAT_803e2fb0;
extern f32 FLOAT_803e2fb4;
extern f32 FLOAT_803e2fb8;
extern f32 FLOAT_803e2fbc;
extern f32 FLOAT_803e2fc8;
extern f32 FLOAT_803e2fcc;
extern f32 FLOAT_803e2fd0;
extern f32 FLOAT_803e2fd4;
extern f32 FLOAT_803e2fd8;
extern f32 FLOAT_803e2fdc;
extern f32 FLOAT_803e2fe0;
extern f32 FLOAT_803e2fe4;
extern f32 FLOAT_803e2fe8;
extern f32 FLOAT_803e2fec;
extern f32 FLOAT_803e2ff0;
extern f32 FLOAT_803e2ff4;
extern f32 FLOAT_803e2ff8;
extern f32 FLOAT_803e2ffc;
extern f32 FLOAT_803e3000;
extern f32 FLOAT_803e3004;
extern f32 FLOAT_803e3008;
extern f32 FLOAT_803e300c;
extern f32 FLOAT_803e3010;
extern f32 FLOAT_803e3014;
extern f32 FLOAT_803e3018;
extern f32 FLOAT_803e3020;
extern f32 FLOAT_803e3024;
extern f32 FLOAT_803e3028;
extern f32 FLOAT_803e302c;
extern f32 FLOAT_803e3030;
extern f32 FLOAT_803e3034;
extern f32 FLOAT_803e3048;
extern f32 FLOAT_803e306c;
extern f32 FLOAT_803e3070;
extern f32 FLOAT_803e3074;
extern f32 FLOAT_803e3078;
extern f32 FLOAT_803e307c;
extern f32 FLOAT_803e3080;
extern f32 FLOAT_803e3084;
extern f32 FLOAT_803e3088;
extern f32 FLOAT_803e3098;
extern f32 FLOAT_803e309c;
extern f32 FLOAT_803e30a8;
extern void* PTR_DAT_8030eac8;
extern void* PTR_DAT_8030eacc;
extern void* PTR_DAT_8031d158;
extern int iRam803dc834;
extern char s_Alignment_8031de30[];
extern char s_Exception__8031de04[];
extern char s_General_Purpose_Registers_8031dec0[];
extern char s_Machine_check_8031de20[];
extern char s_Memory_Protection_Error_8031de6c[];
extern char s_Performance_monitor_8031de3c[];
extern char s_Stack__x__depth__d_8031dea0[];
extern char s_Stack_trace_8031de94[];
extern char s_System_management_interrupt_8031de50[];
extern char s_System_reset_8031de10[];
extern char s_Unknown_error_8031de84[];
extern char s__08x__08x_8031deb4[];
extern char s__08x__08x__08x__08x_8031dedc[];
extern char s__d____d_803dc89c[];
extern char s_errorThreadFunc__x_8031ddf0[];

/*
 * --INFO--
 *
 * Function: Minimap_update
 * EN v1.0 Address: 0x80132024
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801323AC
 * EN v1.1 Size: 5296b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
typedef struct MinimapRow {
    s16 x0, x1, z0, z1, y0, y1;
    u16 gameBit;
    u8  texU, texV;
    u16 mapId;
    u8  swap;
    u8  pad13;
} MinimapRow;

typedef struct MinimapMapEntry {
    MinimapRow *rows;
    u16 gameBit;
    u8  cellId;
    u8  count;
} MinimapMapEntry;

extern MinimapMapEntry lbl_8031C508[];

extern int   coordsToMapCell(f32 x, f32 z);
extern void *Obj_GetPlayerObject(void);
extern u32   GameBit_Get(int eventId);
extern int   Camera_GetViewportYOffset(void);
extern int   objIsCurModelNotZero(int obj);
extern void *gameTextGetBox(int boxId);
extern void  gameTextSetColor(int r, int g, int b, int a);
extern void  gameTextShow(int id);
extern void  GXSetScissor(int x, int y, int w, int h);
extern void  drawTexture(void* tex, f32 x, f32 y, int alpha, int p5);
extern f32   fn_80293E80(f32);
extern f32   sin(f32);
extern void  hudDrawTriangle(f32 x0, f32 y0, f32 x1, f32 y1, f32 x2, f32 y2, u32 *color);
extern void  hudDrawRect(u32 x0, u32 y0, u32 x1, u32 y1, u32 *color);
extern void  drawPartialTexture(void *tex, f32 x, f32 y, int alpha, int scale, u32 w, u32 h, u32 u, u32 v);
extern void  drawHudBox(int id, int x, int y, int w, int alpha, int p6);
extern void  gameTextFn_8001984c(int a, int b, int c);
extern void  gameTextFn_80019804(int n);
extern int   gameTextFn_80019b14(void);
extern void  gameTextSetCharset(int a, int b);
extern void  textureFree(void* tex);
extern void* textureLoadAsset(s32);
void fn_80133718(void);
void fn_8013351C(void);
extern int *gCameraInterface;

extern u8    lbl_803DBBB0;
extern u8    lbl_803DD7BA;
extern s16   lbl_803DD7A2;
extern s16   lbl_803DBA6E;
extern u8    lbl_803DD928;
extern int   lbl_803DD934;
extern u8    pauseMenuState;
extern u8    lbl_803DD75B;
extern s16   lbl_803DD930;
extern s16   lbl_803DD932;
extern u32   lbl_803DD938;
extern void* lbl_803DD92C;
extern void* minimapTexture;
extern void* lbl_803DD940;
extern u8    lbl_803DD946;
extern u8    lbl_803DD947;
extern s16   lbl_803DD948;
extern s16   lbl_803DD94A;
extern s16   lbl_803DBBD0;
extern s16   lbl_803DBBD2;
extern s8    lbl_803DD95C;
extern s8    lbl_803DD944;
extern int   lbl_803DBBC0;
extern int   lbl_803DBBC4;
extern f32   lbl_803DBBB4;
extern f32   lbl_803DBBB8;
extern f32   lbl_803DBBBC;
extern f32   lbl_803DBBEC;
extern f32   lbl_803DD950;
extern f32   lbl_803DD954;
extern f32   lbl_803DD958;
extern u8    framesThisStep;
extern u32   lbl_803E2204;
extern f32   lbl_803E2208;
extern f32   lbl_803E220C;
extern f32   lbl_803E2210;
extern f32   lbl_803E2214;
extern f32   lbl_803E2218;
extern f32   lbl_803E221C;
extern f32   lbl_803E2220;
extern f32   lbl_803E2224;
extern f32   lbl_803E2228;
extern f32   lbl_803E222C;
extern f32   lbl_803E2230;
extern f32   lbl_803E2234;
extern f32   lbl_803E2238;
extern f32   lbl_803E223C;
extern f32   lbl_803E2240;
extern f32   lbl_803E2244;
extern f32   lbl_803E2248;
extern f32   lbl_803E224C;

#pragma scheduling off
#pragma peephole off
int Minimap_update(void)
{
    u8 *player;
    int marker;
    u8 i, k, j, found, cell;
    MinimapRow *rows;
    MinimapRow *row;
    MinimapRow *r2;
    int yi;
    int v;
    s16 m;
    s16 sv, sw;
    int n;
    int w;
    u16 *box;
    u16 hw;
    int cs;
    u32 texW, texH;
    int mx;
    int bw, bh;
    f32 fx, fz;
    f32 ox, oy;
    f32 tw, th;
    f32 xrel, yrel;
    f32 panx, pany;
    f32 t, e, a, b;
    f32 uq, vq, frac;
    u32 u, vv;
    f32 cx, cy;
    f32 c1, s1, c2, s2, c3, s3;
    f32 fv;
    int xc, xl, xr;
    u32 col;
    u32 col2;
    u32 cwRect;
    u32 cwTri1;
    u32 cwTri2;
    u32 cwL;
    u32 cwR;
    u32 cwM;
    u32 cwB;

    marker = 0;
    i = 0;
    k = 0;
    found = 0;
    ox = lbl_803E2208;
    oy = ox;
    col = lbl_803E2204;
    player = Obj_GetPlayerObject();
    if (player != NULL) {
        if (*(void **)(player + 0x30) != NULL) {
            cell = *(u8 *)(*(int *)(player + 0x30) + 0xac);
        } else {
            cell = (u8)coordsToMapCell(*(f32 *)(player + 0xc), *(f32 *)(player + 0x14));
        }
        while (!found && i < 0x19) {
            if (cell == lbl_8031C508[i].cellId && GameBit_Get(lbl_8031C508[i].gameBit) != 0) {
                found = 1;
            } else {
                i++;
            }
        }
        if (found != 0) {
            rows = lbl_8031C508[i].rows;
            if (rows->swap != 0) {
                fx = *(f32 *)(player + 0x20);
                fz = *(f32 *)(player + 0x18);
                lbl_803DD95C = 1;
            } else {
                fx = *(f32 *)(player + 0x18);
                fz = *(f32 *)(player + 0x20);
                lbl_803DD95C = 0;
            }
            yi = (int)*(f32 *)(player + 0x1c);
            for (; k < lbl_8031C508[i].count; k++) {
                row = &rows[k];
                if (fx >= (f32)row->x0 && fx < (f32)row->x1 &&
                    fz >= (f32)row->z0 && fz < (f32)row->z1 &&
                    (s16)yi >= row->y0 && (s16)yi < row->y1 &&
                    GameBit_Get(row->gameBit) != 0) {
                    j = 0;
                    v = rows[k].mapId;
                    if (v != 0) {
                        marker = v;
                    }
                    if ((int)lbl_803DD92C == v) {
                        lbl_803DD948 = -0x8000;
                        lbl_803DD94A = -0x8000;
                        lbl_803DBBD0 = 0x7fff;
                        lbl_803DBBD2 = 0x7fff;
                        for (; j < lbl_8031C508[i].count; j++) {
                            r2 = &rows[j];
                            if (marker == r2->mapId) {
                                m = r2->x0;
                                lbl_803DBBD0 = (m < lbl_803DBBD0) ? m : lbl_803DBBD0;
                                m = r2->x1;
                                lbl_803DD948 = (m > lbl_803DD948) ? m : lbl_803DD948;
                                m = r2->z0;
                                lbl_803DBBD2 = (m < lbl_803DBBD2) ? m : lbl_803DBBD2;
                                m = r2->z1;
                                lbl_803DD94A = (m > lbl_803DD94A) ? m : lbl_803DD94A;
                            }
                        }
                        lbl_803DD946 = rows[k].texU;
                        lbl_803DD947 = rows[k].texV;
                    }
                    break;
                }
            }
        }
        if ((lbl_803DBBB0 == 0 && lbl_803DD7BA == 0) || GameBit_Get(0x58d) != 0) {
            marker = 0;
        }
        if ((**(int (**)(void))((char *)(*gCameraInterface) + 0x10))() == 0x44 ||
            (lbl_803DBBB0 == 0 && lbl_803DD7BA == 0) ||
            (s16)Camera_GetViewportYOffset() != 0 ||
            (*(u16 *)(player + 0xb0) & 0x1000) != 0 ||
            objIsCurModelNotZero((int)player) == 0 ||
            pauseMenuState != 0 || lbl_803DD75B != 0) {
            marker = 0;
            lbl_803DD930 -= 0x20;
            sv = lbl_803DD930;
            if (sv < 0) sv = 0;
            else if (sv > 0xff) sv = 0xff;
            lbl_803DD930 = sv;
            lbl_803DBBC0 -= 10;
            n = lbl_803DBBC0;
            if (n < 0) n = 0;
            else if (n > 500) n = 500;
            lbl_803DBBC0 = n;
            lbl_803DBBC4 -= 10;
            n = lbl_803DBBC4;
            if (n < 0) n = 0;
            else if (n > 500) n = 500;
            lbl_803DBBC4 = n;
        } else {
            lbl_803DBBC4 += 10;
            n = lbl_803DBBC4;
            if (n < 0) n = 0;
            else if (n > 100) n = 100;
            lbl_803DBBC4 = n;
            lbl_803DD930 += 0x20;
            sv = lbl_803DD930;
            if (sv < 0) sv = 0;
            else if (sv > 0xff) sv = 0xff;
            lbl_803DD930 = sv;
        }
        if ((int)lbl_803DD92C == marker) {
            lbl_803DD932 += 0x20;
            sv = lbl_803DD932;
            if (sv < 0) {
                sv = 0;
            } else {
                sv = (sv <= lbl_803DD930) ? sv : lbl_803DD930;
            }
            lbl_803DD932 = sv;
        } else {
            lbl_803DD932 -= 0x20;
            if (lbl_803DD932 < 0) {
                lbl_803DD932 = 0;
                if (minimapTexture != NULL) {
                    textureFree(minimapTexture);
                    minimapTexture = NULL;
                    lbl_803DD92C = NULL;
                }
                if (marker != 0) {
                    minimapTexture = textureLoadAsset(marker);
                    lbl_803DD92C = (void *)marker;
                }
            }
        }
        if (lbl_803DD930 != 0) {
            box = (u16 *)gameTextGetBox(0x83);
            if (lbl_803DD944 == 2 && lbl_803DD7A2 != 0 && lbl_803DBA6E > -1) {
                w = 200;
            } else {
                w = 0x78;
            }
            if (lbl_803DBBC0 < w) {
                n = lbl_803DBBC0 + framesThisStep * 8;
                lbl_803DBBC0 = n;
                lbl_803DBBC0 = (n < w) ? n : w;
            } else {
                n = lbl_803DBBC0 - framesThisStep * 8;
                lbl_803DBBC0 = n;
                lbl_803DBBC0 = (n > w) ? n : w;
            }
            box[4] = (u16)(lbl_803DBBC0 - 8);
            lbl_803DD938 = 0x1b8 - lbl_803DBBC4;
            ((s16 *)box)[0xb] = lbl_803DD938;
            drawHudBox(0x32, (s16)lbl_803DD938, (s16)lbl_803DBBC0, (s16)lbl_803DBBC4,
                       lbl_803DD930 & 0xff, 1);
            GXSetScissor(0x32, lbl_803DD938, lbl_803DBBC0, lbl_803DBBC4);
            switch (lbl_803DD944) {
            case 0:
                if (minimapTexture != NULL) {
                    texW = *(u16 *)((u8 *)minimapTexture + 0xa);
                    texH = *(u16 *)((u8 *)minimapTexture + 0xc);
                    mx = lbl_803DD948;
                    lbl_803DBBEC = (f32)texW / (f32)(mx - lbl_803DBBD0);
                    bw = lbl_803DBBC0;
                    a = (f32)bw / (f32)texW;
                    bh = lbl_803DBBC4;
                    b = (f32)bh / (f32)texH;
                    a = (a < b) ? a : b;
                    a = (a < lbl_803DBBBC) ? a : lbl_803DBBBC;
                    lbl_803DBBB8 = a;
                    if (lbl_803DD95C != 0) {
                        xrel = -*(f32 *)(player + 0x20) + (f32)mx;
                        yrel = *(f32 *)(player + 0x18) - (f32)lbl_803DBBD2;
                    } else {
                        xrel = -*(f32 *)(player + 0x18) + (f32)mx;
                        yrel = -*(f32 *)(player + 0x20) + (f32)lbl_803DD94A;
                    }
                    tw = (f32)texW * lbl_803DBBB4;
                    e = ((f32)bw - tw) * lbl_803E220C;
                    t = lbl_803E2208;
                    t = (t > e) ? t : e;
                    panx = -t;
                    th = (f32)texH * lbl_803DBBB4;
                    e = ((f32)bh - th) * lbl_803E220C;
                    t = lbl_803E2208;
                    t = (t > e) ? t : e;
                    pany = -t;
                    t = lbl_803E2208;
                    if (t == panx) {
                        a = lbl_803DBBB4 * (xrel * lbl_803DBBEC) - (f32)(bw / 2);
                        t = (t > a) ? t : a;
                        b = tw - (f32)bw;
                        t = (t < b) ? t : b;
                        ox = t;
                    }
                    t = lbl_803E2208;
                    if (t == pany) {
                        a = lbl_803DBBB4 * (yrel * lbl_803DBBEC) - (f32)(bh / 2);
                        t = (t > a) ? t : a;
                        b = th - (f32)bh;
                        t = (t < b) ? t : b;
                        oy = t;
                    }
                    uq = ox / lbl_803DBBB4;
                    u = (u32)uq;
                    frac = lbl_803DBBB4 * (uq - (f32)u);
                    vq = oy / lbl_803DBBB4;
                    vv = (u32)vq;
                    ((u8 *)&col)[3] = (u8)lbl_803DD932;
                    ((u8 *)&col)[0] = 0x20;
                    ((u8 *)&col)[1] = 0x4d;
                    ((u8 *)&col)[2] = 0x84;
                    cwRect = col;
                    hudDrawRect(0x32, lbl_803DD938, bw + 0x32, lbl_803DD938 + bh, &cwRect);
                    drawPartialTexture(minimapTexture,
                                       (lbl_803E2210 - panx) - frac,
                                       ((f32)(int)lbl_803DD938 - pany) - lbl_803DBBB4 * (vq - (f32)vv),
                                       (u8)lbl_803DD932,
                                       (int)(lbl_803E2214 * lbl_803DBBB4),
                                       texW - u, texH - vv, u, vv);
                    cx = lbl_803E220C +
                         ((lbl_803DBBB4 * (xrel * lbl_803DBBEC) + lbl_803E2210) - ox - panx);
                    cy = lbl_803E220C +
                         ((lbl_803DBBB4 * (yrel * lbl_803DBBEC) + (f32)(int)lbl_803DD938) - oy - pany);
                    ((u8 *)&col)[3] = (u8)lbl_803DD932;
                    ((u8 *)&col)[0] = 0;
                    ((u8 *)&col)[1] = 0;
                    ((u8 *)&col)[2] = 0;
                    lbl_803DD958 = lbl_803E2218;
                    fv = lbl_803E221C;
                    lbl_803DD954 = fv;
                    lbl_803DD950 = fv;
                    c1 = lbl_803DD958 * fn_80293E80(lbl_803E2220 * (f32)*(s16 *)player / lbl_803E2224);
                    s1 = lbl_803DD958 * sin(lbl_803E2220 * (f32)*(s16 *)player / lbl_803E2224);
                    c2 = lbl_803DD954 *
                         fn_80293E80(lbl_803E2220 * (f32)(*(s16 *)player + 0x6000) / lbl_803E2224);
                    s2 = lbl_803DD954 *
                         sin(lbl_803E2220 * (f32)(*(s16 *)player + 0x6000) / lbl_803E2224);
                    c3 = lbl_803DD950 *
                         fn_80293E80(lbl_803E2220 * (f32)(*(s16 *)player - 0x6000) / lbl_803E2224);
                    s3 = lbl_803DD950 *
                         sin(lbl_803E2220 * (f32)(*(s16 *)player - 0x6000) / lbl_803E2224);
                    cwTri1 = col;
                    hudDrawTriangle(cx - c1, cy - s1, cx - c2, cy - s2, cx - c3, cy - s3, &cwTri1);
                    ((u8 *)&col)[3] = (u8)lbl_803DD932;
                    ((u8 *)&col)[0] = 0xff;
                    ((u8 *)&col)[1] = 0xff;
                    ((u8 *)&col)[2] = 0;
                    c1 = lbl_803E2228 * fn_80293E80(lbl_803E2220 * (f32)*(s16 *)player / lbl_803E2224);
                    s1 = lbl_803E2228 * sin(lbl_803E2220 * (f32)*(s16 *)player / lbl_803E2224);
                    c2 = lbl_803E222C *
                         fn_80293E80(lbl_803E2220 * (f32)(*(s16 *)player + 0x6000) / lbl_803E2224);
                    s2 = lbl_803E222C *
                         sin(lbl_803E2220 * (f32)(*(s16 *)player + 0x6000) / lbl_803E2224);
                    c3 = lbl_803E222C *
                         fn_80293E80(lbl_803E2220 * (f32)(*(s16 *)player - 0x6000) / lbl_803E2224);
                    s3 = lbl_803E222C *
                         sin(lbl_803E2220 * (f32)(*(s16 *)player - 0x6000) / lbl_803E2224);
                    cwTri2 = col;
                    hudDrawTriangle(cx - c1, cy - s1, cx - c2, cy - s2, cx - c3, cy - s3, &cwTri2);
                } else {
                    gameTextFn_8001984c(box[1], box[5], 1);
                    gameTextFn_80019804(1);
                    n = lbl_803DBBC0;
                    box[4] = (u16)((n > 2) ? n : 2);
                    hw = box[4];
                    box[4] = (hw < box[0]) ? hw : box[0];
                    n = lbl_803DBBC4;
                    box[5] = (u16)((n > 2) ? n : 2);
                    gameTextFn_8001984c(box[0], box[5], 2);
                    gameTextSetColor(0, 0xff, 0, lbl_803DD930 & 0xff);
                    cs = gameTextFn_80019b14();
                    gameTextSetCharset(3, 3);
                    gameTextShow(0x458);
                    gameTextSetCharset(cs, 3);
                    gameTextFn_80019804(2);
                }
                break;
            case 1:
                fn_80133718();
                if (lbl_803DD934 == 0) {
                    fn_8013351C();
                    gameTextFn_8001984c(box[1], box[5], 1);
                    gameTextFn_80019804(1);
                    n = lbl_803DBBC0;
                    box[4] = (u16)((n > 2) ? n : 2);
                    hw = box[4];
                    box[4] = (hw < box[0]) ? hw : box[0];
                    n = lbl_803DBBC4;
                    box[5] = (u16)((n > 2) ? n : 2);
                    gameTextFn_8001984c(box[0], box[5], 2);
                    gameTextSetColor(0, 0xff, 0, lbl_803DD930 & 0xff);
                    cs = gameTextFn_80019b14();
                    gameTextSetCharset(3, 3);
                    gameTextShow(0x459);
                    gameTextSetCharset(cs, 3);
                    gameTextFn_80019804(2);
                }
                break;
            case 2:
                if (lbl_803DD7A2 != 0 && lbl_803DBA6E > -1) {
                    if (lbl_803DD928 == 0) {
                        gameTextFn_8001984c(box[1], box[5], 1);
                        gameTextFn_80019804(1);
                        box[4] = (u16)lbl_803DBBC0;
                        box[5] = (u16)lbl_803DBBC4;
                        gameTextFn_8001984c(box[1], box[5], 2);
                        gameTextSetColor(0, 0xff, 0, lbl_803DD7A2 & 0xff);
                        gameTextShow(lbl_803DBA6E + 10000);
                        gameTextFn_80019804(2);
                    }
                } else if (lbl_803DBBB0 != 0) {
                    fn_8013351C();
                    gameTextFn_8001984c(box[1], box[5], 1);
                    gameTextFn_80019804(1);
                    n = lbl_803DBBC0;
                    box[4] = (u16)((n > 2) ? n : 2);
                    hw = box[4];
                    box[4] = (hw < box[0]) ? hw : box[0];
                    n = lbl_803DBBC4;
                    box[5] = (u16)((n > 2) ? n : 2);
                    gameTextFn_8001984c(box[0], box[5], 2);
                    gameTextSetColor(0, 0xff, 0, lbl_803DD930 & 0xff);
                    cs = gameTextFn_80019b14();
                    gameTextSetCharset(3, 3);
                    gameTextShow(0x45a);
                    gameTextSetCharset(cs, 3);
                    gameTextFn_80019804(2);
                }
                break;
            }
            GXSetScissor(0, 0, 0x280, 0x1e0);
            drawTexture(lbl_803DD940, lbl_803E2230, (f32)(int)(lbl_803DD938 - 0x14),
                        lbl_803DD930 & 0xff, 0x100);
            if (lbl_803DD930 != 0) {
                ((u8 *)&col2)[3] = (u8)lbl_803DD932;
                ((u8 *)&col2)[0] = 0xff;
                ((u8 *)&col2)[1] = 0xff;
                ((u8 *)&col2)[2] = 0;
                xc = (s16)(lbl_803DD938 - 4);
                if (lbl_803DD944 == 0 && minimapTexture != NULL) {
                    if (lbl_803DBBB4 < lbl_803DBBBC) {
                        cwL = col2;
                        hudDrawTriangle(lbl_803E2234, (f32)(xc - 0x14),
                                        lbl_803E2238, (f32)(xc - 0x14),
                                        lbl_803E223C, (f32)(xc - 0x1a), &cwL);
                    }
                    if (lbl_803DBBB4 > lbl_803DBBB8) {
                        cwR = col2;
                        hudDrawTriangle(lbl_803E2234, (f32)(xc + 0x14),
                                        lbl_803E2238, (f32)(xc + 0x14),
                                        lbl_803E223C, (f32)(xc + 0x1a), &cwR);
                    }
                }
                xl = xc - 4;
                xr = xc + 4;
                cwM = col2;
                hudDrawTriangle(lbl_803E2240, (f32)xl, lbl_803E2240, (f32)xr,
                                lbl_803E2244, (f32)xc, &cwM);
                cwB = col2;
                hudDrawTriangle(lbl_803E2248, (f32)xl, lbl_803E2248, (f32)xr,
                                lbl_803E224C, (f32)xc, &cwB);
            }
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80132028
 * EN v1.0 Address: 0x80132028
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x8013385C
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_80132028(void)
{
  return DAT_803de5b8 & 0xffff;
}

/*
 * --INFO--
 *
 * Function: FUN_80132034
 * EN v1.0 Address: 0x80132034
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x80133868
 * EN v1.1 Size: 60b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80132034(void)
{
  bool bVar1;
  
  bVar1 = false;
  if ((DAT_803de5c4 == '\x02') && (DAT_803dc818 != '\0')) {
    bVar1 = true;
  }
  if (!bVar1) {
    return;
  }
  DAT_803de5a8 = 5;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80132068
 * EN v1.0 Address: 0x80132068
 * EN v1.0 Size: 544b
 * EN v1.1 Address: 0x801338A4
 * EN v1.1 Size: 508b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80132068(void)
{
  double dVar1;
  double dVar2;
  double in_f27;
  double dVar3;
  double in_f28;
  double dVar4;
  double in_f29;
  double dVar5;
  double in_f30;
  double dVar6;
  double in_f31;
  double dVar7;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined4 local_78;
  undefined4 local_74;
  undefined4 local_70;
  uint uStack_6c;
  undefined4 local_68;
  uint uStack_64;
  undefined4 local_60;
  uint uStack_5c;
  float local_48;
  float fStack_44;
  float local_38;
  float fStack_34;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  local_48 = (float)in_f27;
  fStack_44 = (float)in_ps27_1;
  local_74 = CONCAT31((int3)((uint)DAT_803e2e90 >> 8),(char)DAT_803de5b0);
  FLOAT_803de5cc = -(FLOAT_803e2ef0 * FLOAT_803dc074 - FLOAT_803de5cc);
  if (FLOAT_803e2eb4 < FLOAT_803de5cc) {
    FLOAT_803de5cc = FLOAT_803de5cc - FLOAT_803e2ef4;
  }
  dVar1 = (double)FUN_80293f90();
  dVar7 = (double)(float)((double)FLOAT_803e2ef8 * dVar1);
  dVar1 = (double)FUN_80294964();
  dVar6 = (double)(float)((double)FLOAT_803e2ef8 * dVar1);
  dVar1 = (double)FUN_80293f90();
  dVar5 = (double)(float)((double)FLOAT_803e2efc * dVar1);
  dVar1 = (double)FUN_80294964();
  dVar4 = (double)(float)((double)FLOAT_803e2efc * dVar1);
  dVar1 = (double)FUN_80293f90();
  dVar3 = (double)(float)((double)FLOAT_803e2efc * dVar1);
  dVar1 = (double)FUN_80294964();
  local_78 = local_74;
  dVar2 = (double)FLOAT_803e2f08;
  uStack_6c = DAT_803de5b8 + 0x32U ^ 0x80000000;
  local_70 = 0x43300000;
  local_68 = 0x43300000;
  local_60 = 0x43300000;
  uStack_64 = uStack_6c;
  uStack_5c = uStack_6c;
  FUN_80070414((double)(float)(dVar2 - dVar7),
               (double)(float)((f64)(f32)(s32)uStack_6c - dVar6),
               (double)(float)(dVar2 - dVar5),
               (double)(float)((f64)(f32)(s32)uStack_6c - dVar4),
               (double)(float)(dVar2 - dVar3),
               (double)((f32)(s32)uStack_6c -
                       (float)((double)FLOAT_803e2efc * dVar1)),&local_78);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80132288
 * EN v1.0 Address: 0x80132288
 * EN v1.0 Size: 240b
 * EN v1.1 Address: 0x80133AA0
 * EN v1.1 Size: 256b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80132288(void)
{
  int iVar1;
  int iVar2;
  byte bVar3;
  byte bVar4;
  
  FUN_80286840();
  bVar4 = 2;
  FUN_80129ff8((double)FLOAT_803e2f0c,(double)FLOAT_803e2f08,(double)FLOAT_803e2f10);
  bVar3 = DAT_803de5aa >> 3 & 1;
  if ((bVar3 != 0) && (*(char *)(iRam803dc834 + 0xad) == '\0')) {
    FUN_80006824(0,0x3f1);
  }
  *(byte *)(iRam803dc834 + 0xad) = bVar3;
  if (DAT_803de5b4 == 0) {
    bVar4 = 1;
  }
  for (bVar3 = 0; bVar3 < bVar4; bVar3 = bVar3 + 1) {
    iVar1 = (uint)bVar3 * 4;
    FUN_8003b878(0,0,0,0,*(int *)(&DAT_803dc830 + iVar1),1);
    iVar2 = FUN_80017a54(*(int *)(&DAT_803dc830 + iVar1));
    *(ushort *)(iVar2 + 0x18) = *(ushort *)(iVar2 + 0x18) & ~0x8;
    *(undefined *)(*(int *)(&DAT_803dc830 + iVar1) + 0x37) = 0xff;
  }
  FUN_80129fb0();
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80132378
 * EN v1.0 Address: 0x80132378
 * EN v1.0 Size: 472b
 * EN v1.1 Address: 0x80133BA0
 * EN v1.1 Size: 284b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80132378(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  int iVar1;
  undefined2 *puVar2;
  undefined4 uVar3;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  byte bVar4;
  undefined8 extraout_f1;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  
  dVar5 = (double)FLOAT_803e2f14;
  dVar6 = (double)FLOAT_803e2f18;
  dVar7 = (double)FLOAT_803e2e98;
  dVar8 = (double)FLOAT_803e2f1c;
  dVar9 = (double)FLOAT_803e2f20;
  for (bVar4 = 0; bVar4 < 2; bVar4 = bVar4 + 1) {
    puVar2 = FUN_80017aa4(0x20,bVar4 + 0x7da);
    uVar3 = FUN_80017ae4(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,4,
                         0xff,0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
    iVar1 = (uint)bVar4 * 4;
    *(undefined4 *)(&DAT_803dc830 + iVar1) = uVar3;
    *(float *)(*(int *)(&DAT_803dc830 + iVar1) + 0xc) = (float)dVar5;
    *(float *)(*(int *)(&DAT_803dc830 + iVar1) + 0x10) = (float)dVar6;
    *(float *)(*(int *)(&DAT_803dc830 + iVar1) + 0xc) = (float)dVar7;
    *(float *)(*(int *)(&DAT_803dc830 + iVar1) + 0x10) = (float)dVar7;
    *(float *)(*(int *)(&DAT_803dc830 + iVar1) + 0x14) = (float)dVar8;
    **(undefined2 **)(&DAT_803dc830 + iVar1) = 2000;
    *(undefined2 *)(*(int *)(&DAT_803dc830 + iVar1) + 2) = 0;
    *(float *)(*(int *)(&DAT_803dc830 + iVar1) + 8) = (float)dVar9;
    param_1 = extraout_f1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80132550
 * EN v1.0 Address: 0x80132550
 * EN v1.0 Size: 56b
 * EN v1.1 Address: 0x80133CBC
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80132550(void)
{
  if (DAT_803de5bc != 0) {
    FUN_80053754();
    DAT_803de5bc = 0;
    DAT_803de5ac = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80132588
 * EN v1.0 Address: 0x80132588
 * EN v1.0 Size: 1720b
 * EN v1.1 Address: 0x80133CF4
 * EN v1.1 Size: 1336b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80132588(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  bool bVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  char cVar5;
  short sVar6;
  int iVar7;
  int iVar8;
  uint uVar9;
  uint uVar10;
  short *psVar11;
  ushort uVar12;
  undefined8 extraout_f1;
  undefined8 uVar13;
  double dVar14;
  float local_18 [3];
  
  local_18[0] = FLOAT_803e2f24;
  uVar12 = 0;
  iVar7 = FUN_80017a98();
  if (((((iVar7 == 0) || (iVar8 = (**(code **)(*DAT_803dd6d0 + 0x10))(), iVar8 == 0x44)) ||
       (iVar8 = FUN_800069c0(), (short)iVar8 != 0)) ||
      (((*(ushort *)(iVar7 + 0xb0) & 0x1000) != 0 || (uVar9 = FUN_80294be4(iVar7), uVar9 == 0)))) ||
     (DAT_803de400 != '\0')) {
    if (DAT_803de5c5 != '\0') {
      FUN_80006810(0,0x3f0);
      DAT_803de5c5 = '\0';
    }
  }
  else {
    if (DAT_803de5a8 != '\0') {
      DAT_803de5a8 = DAT_803de5a8 + -1;
    }
    iVar8 = (**(code **)(*DAT_803dd6e8 + 0x20))(0xc8d);
    uVar13 = extraout_f1;
    if (iVar8 != 0) {
      DAT_803dc818 = '\x01' - DAT_803dc818;
      if (DAT_803dc818 == '\x01') {
        uVar12 = 0x3eb;
      }
      else if (DAT_803dc818 == '\0') {
        uVar12 = 0x3ec;
      }
      uVar13 = FUN_80006824(0,uVar12);
    }
    uVar12 = 0;
    if ((DAT_803dc818 == '\0') && (DAT_803de43a == '\0')) {
      if (DAT_803de5c5 != '\0') {
        FUN_80006810(0,0x3f0);
        DAT_803de5c5 = '\0';
      }
    }
    else {
      if (DAT_803de5a9 == '\0') {
        DAT_803de5a9 = '\x01';
        FUN_80132378(uVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      }
      uVar9 = FUN_80006c10(0);
      uVar10 = FUN_80006c00(0);
      if ((uVar9 & 0xc) == 0) {
        if ((uVar10 & 1) == 0) {
          if ((uVar10 & 2) != 0) {
            DAT_803de5c4 = DAT_803de5c4 + '\x01';
            uVar12 = 0x3ed;
            if ('\x02' < DAT_803de5c4) {
              DAT_803de5c4 = '\0';
            }
          }
        }
        else {
          DAT_803de5c4 = DAT_803de5c4 + -1;
          uVar12 = 0x3ed;
          if (DAT_803de5c4 < '\0') {
            DAT_803de5c4 = '\x02';
          }
        }
      }
      if (DAT_803de43a == '\0') {
        if (DAT_803dc819 != -1) {
          DAT_803de5c4 = DAT_803dc819;
          DAT_803dc819 = -1;
        }
      }
      else {
        if (DAT_803dc819 == -1) {
          DAT_803dc819 = DAT_803de5c4;
        }
        DAT_803de5c4 = '\x02';
      }
      if (DAT_803de5c4 == '\x01') {
        if (DAT_803de5c5 != '\0') {
          FUN_80006810(0,0x3f0);
          DAT_803de5c5 = '\0';
        }
        DAT_803de5b4 = ObjGroup_FindNearestObject(0x4f,iVar7,local_18);
        if (DAT_803de5b4 != 0) {
          if (FLOAT_803e2ef0 <= local_18[0]) {
            DAT_803de5aa = '\0';
            cVar5 = DAT_803de5aa;
          }
          else {
            cVar5 = DAT_803de5aa + '\x01';
            if (local_18[0] < FLOAT_803e2f2c) {
              cVar5 = DAT_803de5aa + '\x02';
            }
          }
          DAT_803de5aa = cVar5;
          psVar11 = FUN_800069a8();
          iVar7 = FUN_80017730();
          sVar6 = (*psVar11 + (short)iVar7) - *(short *)(iRam803dc834 + 4);
          if (0x8000 < sVar6) {
            sVar6 = sVar6 + 1;
          }
          if (sVar6 < -0x8000) {
            sVar6 = sVar6 + -1;
          }
          iVar7 = (int)sVar6 / 5 + ((int)sVar6 >> 0x1f);
          *(short *)(iRam803dc834 + 4) =
               *(short *)(iRam803dc834 + 4) + ((short)iVar7 - (short)(iVar7 >> 0x1f));
        }
      }
      else if (DAT_803de5c4 < '\x01') {
        if (-1 < DAT_803de5c4) {
          if ((uVar9 & 4) == 0) {
            if ((uVar9 & 8) == 0) {
              FLOAT_803dc84c = FLOAT_803e2f28;
            }
            else {
              dVar14 = (double)sqrtf_8029312c((double)FLOAT_803dc840,(double)FLOAT_803dc074);
              FLOAT_803dc84c = (float)((double)FLOAT_803dc84c * dVar14);
            }
          }
          else {
            dVar14 = (double)sqrtf_8029312c((double)FLOAT_803dc83c,(double)FLOAT_803dc074);
            FLOAT_803dc84c = (float)((double)FLOAT_803dc84c * dVar14);
          }
          fVar2 = FLOAT_803dc844;
          if ((FLOAT_803dc844 <= FLOAT_803dc84c) &&
             (fVar2 = FLOAT_803dc84c, FLOAT_803dc848 < FLOAT_803dc84c)) {
            fVar2 = FLOAT_803dc848;
          }
          fVar3 = FLOAT_803dc81c * fVar2;
          fVar4 = FLOAT_803dc820;
          if ((FLOAT_803dc820 <= fVar3) && (fVar4 = fVar3, FLOAT_803dc824 < fVar3)) {
            fVar4 = FLOAT_803dc824;
          }
          FLOAT_803dc84c = fVar2;
          if (fVar4 == FLOAT_803dc81c) {
            FLOAT_803dc81c = fVar4;
            if (DAT_803de5c5 != '\0') {
              FUN_80006810(0,0x3f0);
              DAT_803de5c5 = '\0';
            }
          }
          else {
            FLOAT_803dc81c = fVar4;
            if (DAT_803de5c5 == '\0') {
              FUN_80006824(0,0x3f0);
              DAT_803de5c5 = '\x01';
            }
          }
        }
      }
      else if (DAT_803de5c4 < '\x03') {
        if (DAT_803de5c5 != '\0') {
          FUN_80006810(0,0x3f0);
          DAT_803de5c5 = '\0';
        }
        iVar7 = (int)DAT_803dc6d6;
        bVar1 = iVar7 != DAT_803dc850;
        DAT_803dc850 = iVar7;
        if (bVar1) {
          if (iVar7 == -1) {
            uVar12 = 0x3ef;
          }
          else {
            uVar12 = 0x3ee;
          }
        }
      }
      if (uVar12 != 0) {
        FUN_80006824(0,uVar12);
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80132c40
 * EN v1.0 Address: 0x80132C40
 * EN v1.0 Size: 252b
 * EN v1.1 Address: 0x8013422C
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80132c40(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  byte bVar1;
  undefined8 uVar2;
  
  if (DAT_803de5bc != 0) {
    FUN_80053754();
  }
  uVar2 = FUN_80053754();
  for (bVar1 = 0; bVar1 < 2; bVar1 = bVar1 + 1) {
    if (*(int *)(&DAT_803dc830 + (uint)bVar1 * 4) != 0) {
      uVar2 = FUN_80017ac8(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                           *(int *)(&DAT_803dc830 + (uint)bVar1 * 4));
      *(undefined4 *)(&DAT_803dc830 + (uint)bVar1 * 4) = 0;
    }
  }
  DAT_803de5bc = 0;
  DAT_803de5c0 = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80132d3c
 * EN v1.0 Address: 0x80132D3C
 * EN v1.0 Size: 148b
 * EN v1.1 Address: 0x801342C8
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80132d3c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  DAT_803de5c0 = FUN_8005398c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0xbe5,
                              param_10,param_11,param_12,param_13,param_14,param_15,param_16);
  DAT_803de5b8 = 0x154;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80132dd0
 * EN v1.0 Address: 0x80132DD0
 * EN v1.0 Size: 440b
 * EN v1.1 Address: 0x801342F8
 * EN v1.1 Size: 220b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80132dd0(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  byte bVar3;
  undefined4 uVar1;
  int iVar2;
  int *in_r6;
  int in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined8 extraout_f1;
  undefined8 uVar4;
  int local_28;
  int local_24;
  int local_20;
  float local_1c;
  undefined auStack_18 [20];
  
  local_1c = FLOAT_803e2f30;
  local_20 = 0;
  local_24 = 0;
  local_28 = 0;
  bVar3 = FUN_80006b20();
  if (bVar3 != 0) {
    FUN_80006b30(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  }
  uVar1 = FUN_80017a98();
  iVar2 = ObjGroup_FindNearestObject(9,uVar1,&local_1c);
  uVar4 = extraout_f1;
  if (iVar2 != 0) {
    in_r6 = &local_28;
    in_r7 = **(int **)(iVar2 + 0x68);
    uVar4 = (**(code **)(in_r7 + 0x54))(iVar2,&local_20,&local_24);
  }
  local_24 = local_28 - (local_24 - local_20);
  if (local_24 < 0) {
    local_24 = 0;
  }
  FUN_8028fde8(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)auStack_18,
               &DAT_803dc858,local_24,in_r6,in_r7,in_r8,in_r9,in_r10);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80132f88
 * EN v1.0 Address: 0x80132F88
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x801343D4
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80132f88(void)
{
  FUN_80053754();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80132fa8
 * EN v1.0 Address: 0x80132FA8
 * EN v1.0 Size: 140b
 * EN v1.1 Address: 0x801343F8
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80132fa8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  DAT_803de5e0 = FUN_8005398c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x47a,
                              param_10,param_11,param_12,param_13,param_14,param_15,param_16);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80133034
 * EN v1.0 Address: 0x80133034
 * EN v1.0 Size: 848b
 * EN v1.1 Address: 0x80134428
 * EN v1.1 Size: 708b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80133034(void)
{
  float fVar1;
  float fVar2;
  float fVar3;
  double dVar4;
  uint uVar5;
  char cVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  ushort *puVar10;
  undefined8 local_10;
  
  dVar4 = DOUBLE_803e2f50;
  if (DAT_803de5f0 < 10) {
    fVar1 = FLOAT_803de5e8 + FLOAT_803dc074;
    if ((float)((double)CONCAT44(0x43300000,
                                 (uint)*(ushort *)(&DAT_8031d302 + (uint)DAT_803de5f0 * 0x98)) -
               DOUBLE_803e2f50) <= fVar1) {
      DAT_803de5f0 = DAT_803de5f0 + 1;
    }
    FLOAT_803de5e8 = fVar1;
    if (DAT_803de5f0 < 10) {
      iVar9 = 0;
      iVar8 = (uint)DAT_803de5f0 * 0x98;
      for (iVar7 = 0; iVar7 < (int)(uint)(byte)(&DAT_8031d304)[iVar8]; iVar7 = iVar7 + 1) {
        puVar10 = (ushort *)(&DAT_8031d270 + iVar9 + iVar8);
        uVar5 = (uint)*puVar10;
        if ((float)((double)CONCAT44(0x43300000,uVar5) - dVar4) <= fVar1) {
          if ((float)((double)CONCAT44(0x43300000,(uint)puVar10[1]) - dVar4) <= fVar1) {
            uVar5 = (uint)puVar10[2];
            local_10 = (double)CONCAT44(0x43300000,uVar5);
            if ((float)(local_10 - dVar4) <= fVar1) {
              local_10 = (double)CONCAT44(0x43300000,(uint)puVar10[3]);
              if ((float)(local_10 - dVar4) <= fVar1) {
                cVar6 = '\0';
              }
              else {
                local_10 = (double)CONCAT44(0x43300000,uVar5);
                fVar2 = (fVar1 - (float)(local_10 - dVar4)) /
                        (f32)(s32)(puVar10[3] - uVar5);
                fVar3 = FLOAT_803e2f38;
                if ((FLOAT_803e2f38 <= fVar2) && (fVar3 = fVar2, FLOAT_803e2f3c < fVar2)) {
                  fVar3 = FLOAT_803e2f3c;
                }
                cVar6 = -1 - (char)(int)(FLOAT_803e2f40 * fVar3);
              }
            }
            else {
              cVar6 = -1;
            }
          }
          else {
            local_10 = (double)CONCAT44(0x43300000,puVar10[1] - uVar5 ^ 0x80000000);
            fVar2 = (fVar1 - (float)((double)CONCAT44(0x43300000,uVar5) - dVar4)) /
                    (float)(local_10 - DOUBLE_803e2f58);
            fVar3 = FLOAT_803e2f38;
            if ((FLOAT_803e2f38 <= fVar2) && (fVar3 = fVar2, FLOAT_803e2f3c < fVar2)) {
              fVar3 = FLOAT_803e2f3c;
            }
            cVar6 = (char)(int)(FLOAT_803e2f40 * fVar3);
          }
        }
        else {
          cVar6 = '\0';
        }
        *(char *)((int)puVar10 + 0xb) = cVar6;
        local_10 = (double)CONCAT44(0x43300000,(uint)*puVar10);
        if ((((float)(local_10 - dVar4) <= fVar1) &&
            (local_10 = (double)CONCAT44(0x43300000,(uint)puVar10[3]),
            fVar1 <= (float)(local_10 - dVar4))) &&
           (local_10 = (double)CONCAT44(0x43300000,
                                        (uint)*(ushort *)(&DAT_8031d300 + (uint)DAT_803de5f0 * 0x98)
                                       ), (float)(local_10 - dVar4) <= fVar1)) {
          *(float *)(puVar10 + 6) =
               FLOAT_803e2f44 * (FLOAT_803dc074 / FLOAT_803e2f48) + *(float *)(puVar10 + 6);
        }
        iVar9 = iVar9 + 0x10;
      }
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80133384
 * EN v1.0 Address: 0x80133384
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x801346EC
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80133384(void)
{
  FUN_80053754();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801333a4
 * EN v1.0 Address: 0x801333A4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80134710
 * EN v1.1 Size: 68b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801333a4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801333a8
 * EN v1.0 Address: 0x801333A8
 * EN v1.0 Size: 296b
 * EN v1.1 Address: 0x80134754
 * EN v1.1 Size: 304b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801333a8(undefined4 param_1,undefined4 param_2,short *param_3,int param_4,int *param_5)
{
  uint uVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  char cVar5;
  uint uVar6;
  uint uVar7;
  short *psVar8;
  uint uVar9;
  undefined8 uVar10;
  
  uVar10 = FUN_80286830();
  uVar9 = 0;
  iVar3 = 0;
  psVar8 = param_3;
  for (iVar4 = 0; iVar4 < param_4; iVar4 = iVar4 + 1) {
    uVar1 = FUN_80017690((int)*psVar8);
    if (uVar1 != 0) {
      iVar3 = iVar3 + 1;
    }
    psVar8 = psVar8 + 2;
  }
  iVar3 = ((param_4 - iVar3) * 0x2a) / 2 + 0x52;
  cVar5 = '\0';
  for (iVar4 = 0; uVar7 = (uint)((ulonglong)uVar10 >> 0x20), uVar1 = (uint)uVar10, iVar4 < param_4;
      iVar4 = iVar4 + 1) {
    uVar2 = FUN_80017690((int)*param_3);
    uVar6 = uVar1;
    if (uVar2 != 0) {
      FUN_80003494(uVar1,uVar7,0x3c);
      *(short *)(uVar1 + 6) = (short)iVar3;
      *(char *)(uVar1 + 0x1a) = cVar5 + -1;
      *(char *)(uVar1 + 0x1b) = cVar5 + '\x01';
      *param_5 = iVar4;
      param_5 = param_5 + 1;
      uVar6 = uVar1 + 0x3c;
      iVar3 = iVar3 + 0x2a;
      cVar5 = cVar5 + '\x01';
      uVar9 = uVar1;
    }
    param_3 = param_3 + 2;
    uVar10 = CONCAT44(uVar7 + 0x3c,uVar6);
  }
  if (uVar9 != 0) {
    *(undefined *)(uVar9 + 0x1b) = 0xff;
  }
  FUN_8028687c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801334d0
 * EN v1.0 Address: 0x801334D0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80134884
 * EN v1.1 Size: 780b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801334d0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801334d4
 * EN v1.0 Address: 0x801334D4
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x80134B90
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801334d4(void)
{
  FUN_80053754();
  FUN_80053754();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801334f8
 * EN v1.0 Address: 0x801334F8
 * EN v1.0 Size: 328b
 * EN v1.1 Address: 0x80134BBC
 * EN v1.1 Size: 60b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801334f8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  DAT_803de604 = FUN_8005398c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x4fa,
                              param_10,param_11,param_12,param_13,param_14,param_15,param_16);
  DAT_803de600 = FUN_8005398c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x5e3,
                              param_10,param_11,param_12,param_13,param_14,param_15,param_16);
  FLOAT_803de5fc = FLOAT_803e2f70;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80133640
 * EN v1.0 Address: 0x80133640
 * EN v1.0 Size: 336b
 * EN v1.1 Address: 0x80134BF8
 * EN v1.1 Size: 344b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80133640(uint param_1,int param_2)
{
  char cVar1;
  short sVar2;
  int iVar3;
  
  for (iVar3 = 0; iVar3 < *(char *)(param_2 + 0x1b); iVar3 = iVar3 + 1) {
    sVar2 = *(short *)(param_1 + 0x46);
    if (sVar2 == 0x77f) {
      cVar1 = *(char *)(param_2 + iVar3 + 0x13);
      if (cVar1 == '\0') {
        FUN_80006824(param_1,0x36b);
      }
      else if (cVar1 == '\a') {
        FUN_80006824(param_1,0x421);
      }
    }
    else if (sVar2 < 0x77f) {
      if (sVar2 == 0x77d) {
        if (*(char *)(param_2 + iVar3 + 0x13) == '\0') {
          FUN_80006824(param_1,0x368);
        }
      }
      else if (0x77c < sVar2) {
        cVar1 = *(char *)(param_2 + iVar3 + 0x13);
        if (cVar1 == '\0') {
          FUN_80006824(param_1,0x370);
        }
        else if (cVar1 == '\a') {
          FUN_80006824(param_1,0x36c);
        }
      }
    }
    else if (sVar2 < 0x781) {
      cVar1 = *(char *)(param_2 + iVar3 + 0x13);
      if (cVar1 == '\0') {
        FUN_80006824(param_1,0x36a);
      }
      else if (cVar1 == '\a') {
        FUN_80006824(param_1,0x369);
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80133790
 * EN v1.0 Address: 0x80133790
 * EN v1.0 Size: 616b
 * EN v1.1 Address: 0x80134D50
 * EN v1.1 Size: 500b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80133790(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  int iVar1;
  uint uVar2;
  uint uVar3;
  byte bVar4;
  undefined8 uVar5;
  
  uVar3 = (uint)DAT_803de618;
  if (uVar3 < DAT_803dc872) {
    if (DAT_803de628 < 1) {
      uVar2 = (uint)DAT_803de616;
      if (uVar2 < 0x14) {
        bVar4 = (byte)((uVar2 * 0xff) / 0x14);
      }
      else if ((int)uVar2 < (int)(*(ushort *)(&DAT_8031dae2 + uVar3 * 4) - 0x14)) {
        bVar4 = 0xff;
      }
      else {
        if ((uVar3 == DAT_803dc872 - 1) && (DAT_803de624 == 0)) {
          FUN_800067bc(3,2,4000);
          DAT_803de624 = 1;
        }
        iVar1 = ((uint)DAT_803de616 - (uint)*(ushort *)(&DAT_8031dae2 + (uint)DAT_803de618 * 4)) *
                0xff;
        iVar1 = iVar1 / 0x14 + (iVar1 >> 0x1f);
        bVar4 = -((char)iVar1 - (char)(iVar1 >> 0x1f)) - 1;
      }
      uVar5 = FUN_80017484(0xff,0xff,0xff,bVar4);
      FUN_80006c84(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   (uint)*(ushort *)(&DAT_8031dae0 + (uint)DAT_803de618 * 4),0,0);
      DAT_803de614 = DAT_803de614 + (ushort)DAT_803dc071;
      DAT_803de616 = DAT_803de616 + DAT_803dc071;
      if (*(ushort *)(&DAT_8031dae2 + (uint)DAT_803de618 * 4) <= DAT_803de616) {
        uVar3 = DAT_803de618 + 1;
        DAT_803de618 = (ushort)uVar3;
        DAT_803de628 = 0x3c;
        if ((uVar3 & 0xffff) < (uint)DAT_803dc872) {
          DAT_803de616 = 0;
        }
      }
    }
    else {
      DAT_803de628 = DAT_803de628 - (ushort)DAT_803dc071;
      if (DAT_803de628 < 0) {
        DAT_803de628 = 0;
      }
    }
  }
  else {
    iVar1 = (**(code **)(*DAT_803dd6d0 + 0x10))();
    if (iVar1 == 0x57) {
      DAT_803de613 = 0;
      FUN_80006b84(4);
      FUN_80117318(4);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801339f8
 * EN v1.0 Address: 0x801339F8
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x80134F44
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined FUN_801339f8(void)
{
  return DAT_803de613;
}

/*
 * --INFO--
 *
 * Function: FUN_80133a04
 * EN v1.0 Address: 0x80133A04
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x80134F4C
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80133a04(void)
{
  DAT_803de613 = 1;
  DAT_803de614 = 0;
  DAT_803de616 = 0;
  DAT_803de628 = 0;
  DAT_803de618 = 0;
  DAT_803de62a = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80133a28
 * EN v1.0 Address: 0x80133A28
 * EN v1.0 Size: 64b
 * EN v1.1 Address: 0x80134F70
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80133a28(void)
{
  int iVar1;
  undefined4 uVar2;
  
  iVar1 = FUN_80006b7c();
  if ((iVar1 - 2U < 5) || (iVar1 == 7)) {
    uVar2 = 1;
  }
  else {
    uVar2 = 0;
  }
  return uVar2;
}

/*
 * --INFO--
 *
 * Function: FUN_80133a68
 * EN v1.0 Address: 0x80133A68
 * EN v1.0 Size: 468b
 * EN v1.1 Address: 0x80134FB0
 * EN v1.1 Size: 280b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80133a68(double param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 char param_9)
{
  ushort *puVar1;
  undefined *puVar2;
  undefined8 uVar3;
  double dVar4;
  double dVar5;
  
  if (param_9 == '\0') {
    if (DAT_803de620 == '\0') {
      FLOAT_803de61c = FLOAT_803e2fa8;
      param_1 = (double)FLOAT_803de634;
      if ((double)FLOAT_803e2fac < param_1) {
        DAT_803de620 = '\x01';
      }
    }
    else {
      FLOAT_803de61c = FLOAT_803de634;
    }
  }
  else {
    FLOAT_803de61c = FLOAT_803e2fa8;
    DAT_803de620 = '\0';
  }
  puVar1 = FUN_80017470(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x3d9);
  if (*puVar1 != 0xffff) {
    puVar2 = FUN_80006c9c((uint)*(byte *)(puVar1 + 2));
    if (DAT_803de62c == 0) {
      DAT_803de62c = (uint)*(short *)(puVar2 + 0x16);
    }
    dVar5 = (double)FLOAT_803e2fb0;
    dVar4 = (double)(FLOAT_803e2fa8 - FLOAT_803de61c);
    *(short *)(puVar2 + 0x16) =
         (short)(int)(dVar5 * dVar4 +
                     (double)(f32)(s32)(DAT_803de62c));
    uVar3 = FUN_80017484(0xff,0xff,0xff,(byte)(int)(FLOAT_803e2fb4 * FLOAT_803de630));
    FUN_80006c88(uVar3,dVar4,dVar5,param_4,param_5,param_6,param_7,param_8,0x3d9);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80133c3c
 * EN v1.0 Address: 0x80133C3C
 * EN v1.0 Size: 3048b
 * EN v1.1 Address: 0x801350C8
 * EN v1.1 Size: 2772b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80133c3c(undefined4 param_1,undefined4 param_2,uint param_3)
{
  int iVar1;
  float fVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  ushort uVar9;
  undefined *puVar7;
  int iVar8;
  uint uVar10;
  int iVar11;
  uint uVar12;
  double dVar13;
  undefined8 uVar14;
  double dVar15;
  double dVar16;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  ulonglong uVar17;
  undefined8 local_e8;
  undefined8 local_e0;
  undefined8 local_d8;
  undefined8 local_d0;
  undefined8 local_c8;
  undefined8 local_b8;
  undefined8 local_a8;
  undefined8 local_a0;
  undefined8 local_98;
  undefined8 local_88;
  undefined8 local_80;
  undefined8 local_78;
  undefined8 local_70;
  undefined8 local_68;
  undefined8 local_58;
  
  uVar17 = FUN_8028682c();
  uVar4 = (uint)(uVar17 >> 0x20);
  FLOAT_803de644 = FLOAT_803de644 + FLOAT_803dc074;
  if (FLOAT_803e2f80 < FLOAT_803de644) {
    FLOAT_803de644 = FLOAT_803de644 - FLOAT_803e2f80;
  }
  dVar13 = (double)FUN_80294964();
  iVar8 = DAT_803aac08;
  DAT_803de640 = (byte)(int)((double)FLOAT_803e2fbc * dVar13 + (double)FLOAT_803e2fb8);
  if (FLOAT_803e2f88 < FLOAT_803de648) {
    iVar1 = (int)DAT_803aac50;
    iVar11 = (int)DAT_803aac60;
    iVar5 = FUN_80286718((double)(FLOAT_803e2f90 * FLOAT_803de648));
    local_d8 = (double)CONCAT44(0x43300000,
                                iVar1 + -0x32 + (uint)*(ushort *)(DAT_803aac10 + 10) + 0x5a ^
                                0x80000000);
    FUN_800709e0((double)(float)(local_d8 - DOUBLE_803e2f78),
                 (double)(f32)(s32)(iVar11 - 0x10U),iVar8,uVar4,0x100,
                 (uint)*(ushort *)(iVar8 + 10),iVar5 + 0x10,0);
    iVar8 = DAT_803aac10;
    iVar5 = FUN_80286718((double)(FLOAT_803e2f90 * FLOAT_803de648));
    FUN_800709e0((double)(f32)(s32)(iVar1 + 0x28U),
                 (double)(f32)(s32)(iVar11 - 0x10U),iVar8,0xff,0x100,(uint)*(ushort *)(iVar8 + 10),
                 iVar5 + 0x10,0);
    iVar8 = DAT_803aac10;
    uVar9 = *(ushort *)(DAT_803aac10 + 10);
    iVar5 = FUN_80286718((double)(FLOAT_803e2f90 * FLOAT_803de648));
    FUN_800709e0((double)(f32)(s32)(iVar1 + -0x32 + (uint)*(ushort *)(DAT_803aac08 + 10) + (uint)uVar9 +
                                0x57),
                 (double)(f32)(s32)(iVar11 - 0x10U),iVar8,0xff,0x100,(uint)uVar9,iVar5 + 0x10,1);
    iVar8 = DAT_803aabf8;
    iVar5 = FUN_80286718((double)(FLOAT_803e2f90 * FLOAT_803de648));
    FUN_800709e0((double)(f32)(s32)(iVar1 - 0xfU),
                 (double)(f32)(s32)(iVar11 - 0x10U),iVar8,0xff,0x100,
                 (uint)*(ushort *)(iVar8 + 10),iVar5 + 0x10,0);
  }
  iVar8 = (int)DAT_803aac50;
  iVar1 = (int)DAT_803aac60;
  if (FLOAT_803de648 <= FLOAT_803e2f88) {
    uVar12 = (uint)DAT_803de640;
  }
  else {
    uVar12 = 0xff;
  }
  FUN_800709e8((double)(f32)(s32)(iVar8 - 0x18U),(double)(f32)(s32)((iVar1 - (uint)*(ushort *)(DAT_803aabfc + 0xc)) + 3),
               DAT_803aabfc,0xff,0xff);
  FUN_800709e8((double)(f32)(s32)(iVar8 + 0xa1U),(double)(f32)(s32)(iVar1 - 0x2eU),
               DAT_803aac14,uVar12,0xff);
  iVar8 = (int)DAT_803aac50;
  uVar12 = (uint)DAT_803aac60;
  if (FLOAT_803de648 <= FLOAT_803e2f88) {
    uVar10 = (uint)DAT_803de640;
  }
  else {
    uVar10 = 0xff;
  }
  FUN_800709e8((double)(f32)(s32)(iVar8 - 0x18U),
               (double)(FLOAT_803e2f8c +
                       FLOAT_803e2f90 * FLOAT_803de648 + (f32)(s32)(uVar12)),
               DAT_803aac00,0xff,0xff);
  dVar16 = (double)FLOAT_803e2f94;
  dVar15 = (double)FLOAT_803e2f90;
  dVar13 = DOUBLE_803e2f78;
  FUN_800709e8((double)(f32)(s32)(iVar8 + 0xa1U),
               (double)(float)(dVar16 + (double)(float)(dVar15 * (double)FLOAT_803de648 +
                                                       (double)(f32)(s32)(uVar12))),DAT_803aac14,
               uVar10,0xff);
  local_88 = (double)CONCAT44(0x43300000,(uint)DAT_803de640);
  local_88 = local_88 - DOUBLE_803e2fa0;
  uVar14 = FUN_80017484(0xff,0xff,0xff,
                        (byte)(int)(local_88 * (DOUBLE_803e2f98 - (double)FLOAT_803de648)));
  FUN_80006c88(uVar14,local_88,dVar15,dVar16,dVar13,in_f6,in_f7,in_f8,0x3da);
  FUN_800709e8((double)(f32)(s32)((int)DAT_803aac50 - 0x32U),
               (double)(f32)(s32)(0xfe - (*(ushort *)(DAT_803aac04 + 10) >> 1)),DAT_803aac04,0xff,0xff);
  if ((FLOAT_803e2fc8 <= FLOAT_803de648) && ((uVar17 & 0xff) == 0)) {
    iVar8 = (int)DAT_803aac50;
    iVar1 = (int)DAT_803aac60;
    iVar11 = 0;
    dVar15 = (double)FLOAT_803e2f90;
    dVar13 = DOUBLE_803e2f78;
    do {
      iVar5 = DAT_803aac08;
      iVar6 = FUN_80286718((double)(float)(dVar15 * (double)FLOAT_803de648));
      iVar3 = iVar11 + 1;
      local_68 = (double)CONCAT44(0x43300000,
                                  iVar8 + (uint)*(ushort *)(DAT_803aac10 + 10) + 0x28 + iVar3 * -4 ^
                                  0x80000000);
      local_70 = (double)CONCAT44(0x43300000,iVar1 + -0x10 + iVar3 * -3 ^ 0x80000000);
      FUN_800709e0((double)(float)(local_68 - dVar13),(double)(float)(local_70 - dVar13),iVar5,
                   (int)(uint)DAT_803de640 >> (iVar11 + 3U & 0x3f) & 0xff,0x100,
                   (uint)*(ushort *)(iVar5 + 10) + iVar3 * 8,iVar6 + iVar3 * 6 + 0x10,4);
      iVar11 = iVar11 + 1;
    } while (iVar11 < 4);
  }
  if (FLOAT_803e2f88 < FLOAT_803de648) {
    uVar9 = FUN_8013041c();
    if (uVar9 != 0xffff) {
      puVar7 = FUN_80006c9c((uint)uVar9);
      if ((uVar17 & 0xff) == 0) {
        local_70 = (double)CONCAT44(0x43300000,
                                    ((int)*(short *)(puVar7 + 0x16) + (int)DAT_803aac60) - 1U ^
                                    0x80000000);
        FUN_800709e8((double)(f32)(s32)((int)DAT_803aac50 + 0x2fU),
                     (double)(float)(local_70 - DOUBLE_803e2f78),DAT_803aac0c,uVar4,0xff);
      }
    }
  }
  uVar4 = (uint)DAT_803de640;
  local_70 = (double)CONCAT44(0x43300000,(int)(FLOAT_803e2f80 * FLOAT_803de630) - 0x50U ^ 0x80000000
                             );
  FUN_800709e0((double)(float)(local_70 - DOUBLE_803e2f78),
               (double)(f32)(s32)((int)(FLOAT_803e2f84 * FLOAT_803de634) + 0x1e0U),DAT_803aac40,0xff,0x100,
               (uint)*(ushort *)(DAT_803aac40 + 10),(uint)*(ushort *)(DAT_803aac40 + 0xc),1);
  iVar8 = *(int *)(&DAT_803aac18 + ((int)(uVar4 << 3) >> 8) * 4);
  FUN_800709e0((double)(float)((double)CONCAT44(0x43300000,
                                                ((int)(FLOAT_803e2f80 * FLOAT_803de630) +
                                                (uint)*(ushort *)(DAT_803aac40 + 10)) - 0x4a ^
                                                0x80000000) - DOUBLE_803e2f78),
               (double)(f32)(s32)((int)(FLOAT_803e2f84 * FLOAT_803de634) + 0x1e0U),iVar8,0xff,0x100,
               (uint)*(ushort *)(iVar8 + 10),(uint)*(ushort *)(iVar8 + 0xc),0);
  FUN_800709e0((double)(float)((double)CONCAT44(0x43300000,
                                                (0x280 - ((int)(FLOAT_803e2f80 * FLOAT_803de630) +
                                                         -0x50)) -
                                                (uint)*(ushort *)(DAT_803aac40 + 10) ^ 0x80000000) -
                              DOUBLE_803e2f78),
               (double)(float)((double)CONCAT44(0x43300000,
                                                (int)(FLOAT_803e2f84 * FLOAT_803de634) + 0x1e0U ^
                                                0x80000000) - DOUBLE_803e2f78),DAT_803aac40,0xff,
               0x100,(uint)*(ushort *)(DAT_803aac40 + 10),(uint)*(ushort *)(DAT_803aac40 + 0xc),0);
  iVar8 = *(int *)(&DAT_803aac18 + ((int)(uVar4 << 3) >> 8) * 4);
  FUN_800709e0((double)(f32)(s32)(((0x27a - ((int)(FLOAT_803e2f80 * FLOAT_803de630) + -0x50)) -
                              (uint)*(ushort *)(DAT_803aac40 + 10)) - (uint)*(ushort *)(iVar8 + 10)),
               (double)(f32)(s32)((int)(FLOAT_803e2f84 * FLOAT_803de634) + 0x1e0U),iVar8,0xff,0x100,
               (uint)*(ushort *)(iVar8 + 10),(uint)*(ushort *)(iVar8 + 0xc),1);
  fVar2 = FLOAT_803de634;
  if (FLOAT_803de630 < FLOAT_803de634) {
    fVar2 = FLOAT_803de630;
  }
  local_58 = (double)CONCAT44(0x43300000,(int)(FLOAT_803e2fd0 * fVar2 + FLOAT_803e2fcc) ^ 0x80000000
                             );
  FUN_800709e8((double)(f32)(s32)((0x280 - ((int)((uint)*(ushort *)(DAT_803de654 + 10) * 0xbe) >> 8)) /
                              2),
               (double)(float)(local_58 - DOUBLE_803e2f78),DAT_803de654,0xff,0xbe);
  if ((param_3 & 0xff) != 0) {
    iVar8 = (int)DAT_803aac50;
    iVar1 = (int)DAT_803aac60;
    FUN_800709e8((double)(f32)(s32)(iVar8 + 0x2fU),
                 (double)(f32)(s32)(iVar1 + 0x14U),DAT_803aac3c,0xff,0xff);
    FUN_800709e8((double)(f32)(s32)(iVar8 + 0x2fU),
                 (double)(f32)(s32)(iVar1 + 0x4bU),DAT_803aac38,0xff,0xff);
  }
  FUN_80286878();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80134824
 * EN v1.0 Address: 0x80134824
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x80135B9C
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80134824(undefined4 param_1,undefined4 param_2)
{
  DAT_803de63c = param_1;
  DAT_803de638 = param_2;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80134830
 * EN v1.0 Address: 0x80134830
 * EN v1.0 Size: 140b
 * EN v1.1 Address: 0x80135BA8
 * EN v1.1 Size: 136b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80134830(double param_1,double param_2)
{
  FUN_80247a48(param_1,param_2,(double)FLOAT_803e2f88,(undefined4 *)&DAT_803aac44);
  FLOAT_803de648 = (float)((double)FLOAT_803e2fd4 - param_2) / FLOAT_803e2fd8;
  FLOAT_803de634 = (float)(param_1 - (double)FLOAT_803e2fdc) / FLOAT_803e2fe0;
  FLOAT_803de630 = FLOAT_803e2fa8 - FLOAT_803de648;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801348bc
 * EN v1.0 Address: 0x801348BC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80135C30
 * EN v1.1 Size: 488b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801348bc(undefined8 param_1,double param_2,double param_3,double param_4,undefined4 param_5
                 ,undefined4 param_6,short param_7,undefined2 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801348c0
 * EN v1.0 Address: 0x801348C0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80135E18
 * EN v1.1 Size: 352b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801348c0(undefined8 param_1,double param_2,double param_3,double param_4,undefined4 param_5
                 ,undefined4 param_6,undefined2 param_7,undefined2 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801348c4
 * EN v1.0 Address: 0x801348C4
 * EN v1.0 Size: 60b
 * EN v1.1 Address: 0x80135F78
 * EN v1.1 Size: 60b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801348c4(int param_1)
{
  if (*(short *)(param_1 + 0x46) == 0x77d) {
    FUN_800067c0((int *)0x3a,0);
    DAT_803de613 = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80134900
 * EN v1.0 Address: 0x80134900
 * EN v1.0 Size: 148b
 * EN v1.1 Address: 0x80135FB4
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80134900(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  if ((visible != 0) && (DAT_803de62b != '\0')) {
    FUN_8003b818(param_1);
    if ((DAT_803de613 != '\0') && (DAT_803de62a == '\0')) {
      FUN_80017698(0xdf6,1);
      DAT_803de62a = '\x01';
      (**(code **)(*DAT_803dd6d4 + 0x50))(0x57,0,0,0);
      n_attractmode_releaseMovieBuffers();
      DAT_803de624 = 0;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80134994
 * EN v1.0 Address: 0x80134994
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80136050
 * EN v1.1 Size: 2784b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80134994(double param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8,short *param_9,
                 undefined4 param_10,undefined4 param_11,undefined4 param_12,undefined4 param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80134998
 * EN v1.0 Address: 0x80134998
 * EN v1.0 Size: 508b
 * EN v1.1 Address: 0x80136B30
 * EN v1.1 Size: 252b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80134998(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  short sVar1;
  int iVar2;
  double dVar3;
  
  iVar2 = *(int *)(param_9 + 0x5c);
  *(undefined *)(iVar2 + 0x30) = 0;
  *param_9 = (short)((int)*(char *)(param_10 + 0x18) << 8);
  sVar1 = param_9[0x23];
  if ((sVar1 < 0x77d) || (0x780 < sVar1)) {
    dVar3 = (double)FLOAT_803e2f88;
    *(float *)(iVar2 + 0x34) = FLOAT_803e2f88;
    *(undefined *)(iVar2 + 0x31) = 0xfe;
    if (param_9[0x23] == 0x78a) {
      FUN_800305f8(dVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,1,0,
                   param_12,param_13,param_14,param_15,param_16);
    }
    else if (param_9[0x23] == 0x781) {
      FUN_800305f8((double)FLOAT_803e2fa8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,0,0,param_12,param_13,param_14,param_15,param_16);
      FUN_80017964(**(int **)(param_9 + 0x3e),FUN_801184b8);
    }
  }
  else {
    *(char *)(iVar2 + 0x31) = (char)sVar1 + -0x7d;
    *(undefined4 *)(iVar2 + 0x34) = *(undefined4 *)(&DAT_8030eac0 + (short)param_9[0x23] * 0x20);
    FUN_800305f8((double)FLOAT_803e2f88,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0,0,param_12,param_13,param_14,param_15,param_16);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80134b94
 * EN v1.0 Address: 0x80134B94
 * EN v1.0 Size: 28b
 * EN v1.1 Address: 0x80136C2C
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80134b94(char param_1)
{
  if (param_1 == DAT_803de611) {
    return;
  }
  DAT_803dc871 = DAT_803de611;
  DAT_803de611 = param_1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80134bb0
 * EN v1.0 Address: 0x80134BB0
 * EN v1.0 Size: 20b
 * EN v1.1 Address: 0x80136C4C
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80134bb0(undefined param_1)
{
  DAT_803dc870 = DAT_803de610;
  DAT_803de610 = param_1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80134bc4
 * EN v1.0 Address: 0x80134BC4
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x80136C5C
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80134bc4(void)
{
  DAT_803de62b = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80134bd0
 * EN v1.0 Address: 0x80134BD0
 * EN v1.0 Size: 116b
 * EN v1.1 Address: 0x80136C68
 * EN v1.1 Size: 124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80134bd0(void)
{
  int iVar1;
  int *piVar2;
  
  FUN_80053754();
  DAT_803de654 = 0;
  iVar1 = 0;
  piVar2 = &DAT_803aabf8;
  do {
    if (*piVar2 != 0) {
      FUN_80053754();
      *piVar2 = 0;
    }
    piVar2 = piVar2 + 1;
    iVar1 = iVar1 + 1;
  } while (iVar1 < 0x13);
  DAT_803de612 = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80134c44
 * EN v1.0 Address: 0x80134C44
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80136CE4
 * EN v1.1 Size: 228b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80134c44(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80134c48
 * EN v1.0 Address: 0x80134C48
 * EN v1.0 Size: 1012b
 * EN v1.1 Address: 0x80136DC8
 * EN v1.1 Size: 960b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_80134c48(undefined4 param_1,int param_2)
{
  uint uVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  
  if (param_2 < 0x40) {
    if (DAT_803de678 != 0) {
      if (DAT_803de68c != 0) {
        FUN_8004812c(DAT_803de6a4,0);
        FLOAT_803de66c =
             FLOAT_803e3020 /
             (FLOAT_803e3024 *
             (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(DAT_803de6a4 + 10)) -
                    DOUBLE_803e3038));
        FLOAT_803de668 =
             FLOAT_803e3020 /
             (FLOAT_803e3024 *
             (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(DAT_803de6a4 + 0xc)) -
                    DOUBLE_803e3038));
      }
      DAT_803de678 = 0;
    }
    param_2 = param_2 + -0x21;
  }
  else if (param_2 < 0x60) {
    if (DAT_803de678 != 1) {
      if (DAT_803de68c != 0) {
        FUN_8004812c(DAT_803de6a0,0);
        FLOAT_803de66c =
             FLOAT_803e3020 /
             (FLOAT_803e3024 *
             (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(DAT_803de6a0 + 10)) -
                    DOUBLE_803e3038));
        FLOAT_803de668 =
             FLOAT_803e3020 /
             (FLOAT_803e3024 *
             (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(DAT_803de6a0 + 0xc)) -
                    DOUBLE_803e3038));
      }
      DAT_803de678 = 1;
    }
    param_2 = param_2 + -0x40;
  }
  else if (param_2 < 0x80) {
    if (DAT_803de678 != 2) {
      if (DAT_803de68c != 0) {
        FUN_8004812c(DAT_803de69c,0);
        FLOAT_803de66c =
             FLOAT_803e3020 /
             (FLOAT_803e3024 *
             (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(DAT_803de69c + 10)) -
                    DOUBLE_803e3038));
        FLOAT_803de668 =
             FLOAT_803e3020 /
             (FLOAT_803e3024 *
             (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(DAT_803de69c + 0xc)) -
                    DOUBLE_803e3038));
      }
      DAT_803de678 = 2;
    }
    param_2 = param_2 + -0x60;
  }
  iVar3 = DAT_803de678 * 0x40 + -0x7fce2410;
  uVar5 = (uint)*(byte *)(iVar3 + param_2 * 2);
  uVar4 = (*(byte *)(iVar3 + param_2 * 2 + 1) - uVar5) + 1;
  if (DAT_803de68c != 0) {
    uVar1 = (uint)((float)((double)CONCAT44(0x43300000,(uint)DAT_803de69a) - DOUBLE_803e3038) *
                  (FLOAT_803de658 +
                  (float)((double)CONCAT44(0x43300000,(uint)DAT_803de660) - DOUBLE_803e3038)));
    uVar2 = (uint)((float)((double)CONCAT44(0x43300000,(uint)DAT_803de698) - DOUBLE_803e3038) *
                  (FLOAT_803de65c +
                  (float)((double)CONCAT44(0x43300000,(uint)DAT_803de661) - DOUBLE_803e3038)));
    FUN_800713a4();
    FUN_8007089c((double)((f32)(s32)(uVar5 << 5) * FLOAT_803de66c),(double)FLOAT_803e3030,
                 (double)(FLOAT_803de66c *
                         (float)((double)CONCAT44(0x43300000,(uVar5 + uVar4) * 0x20 ^ 0x80000000) -
                                DOUBLE_803e3040)),(double)(FLOAT_803e3034 * FLOAT_803de668),
                 uVar1 << 2,uVar2 << 2,
                 (short)(int)(FLOAT_803e3028 *
                             ((f32)(s32)(uVar4) *
                              (FLOAT_803de658 +
                              (float)((double)CONCAT44(0x43300000,(uint)DAT_803de660) -
                                     DOUBLE_803e3038)) +
                             (f32)(s32)(uVar1))),
                 (short)(int)(FLOAT_803e3028 *
                             (FLOAT_803e302c *
                              (FLOAT_803de65c +
                              (float)((double)CONCAT44(0x43300000,(uint)DAT_803de661) -
                                     DOUBLE_803e3038)) +
                             (f32)(s32)(uVar2))));
  }
  return uVar4;
}

/*
 * --INFO--
 *
 * Function: FUN_8013503c
 * EN v1.0 Address: 0x8013503C
 * EN v1.0 Size: 1856b
 * EN v1.1 Address: 0x80137188
 * EN v1.1 Size: 1824b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8013503c(void)
{
  byte bVar1;
  undefined4 uVar2;
  uint uVar3;
  undefined4 uVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  uint uVar12;
  uint uVar13;
  byte *pbVar14;
  byte *pbVar15;
  double in_f29;
  double dVar16;
  double in_f30;
  double dVar17;
  double in_f31;
  double dVar18;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar19;
  undefined4 local_a8;
  undefined4 local_a4;
  undefined4 local_a0;
  undefined4 local_9c;
  undefined4 local_98;
  undefined4 local_94;
  undefined4 local_90;
  undefined4 local_8c;
  undefined4 local_88;
  uint uStack_84;
  undefined4 local_80;
  uint uStack_7c;
  undefined4 local_78;
  uint uStack_74;
  undefined4 local_70;
  uint uStack_6c;
  undefined4 local_68;
  uint uStack_64;
  undefined4 local_60;
  uint uStack_5c;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  uVar19 = FUN_8028682c();
  uVar4 = (undefined4)((ulonglong)uVar19 >> 0x20);
  pbVar14 = (byte *)uVar19;
  dVar17 = DOUBLE_803e3038;
  dVar18 = DOUBLE_803e3040;
  do {
    uVar13 = (uint)*pbVar14;
    pbVar15 = pbVar14 + 1;
    if (uVar13 == 0) {
      FUN_80286878();
      return;
    }
    uVar12 = 0;
    if (uVar13 == 0x82) {
      if (DAT_803de68c == 0) {
        iVar5 = DAT_803de698 + 10;
        uVar11 = (uint)DAT_803de694;
        uVar10 = (uint)DAT_803de696;
        uVar3 = countLeadingZeros(DAT_803de69a - uVar10);
        uVar9 = countLeadingZeros(iVar5 - uVar11);
        if (uVar3 >> 5 == 0 && uVar9 >> 5 == 0) {
          if (1 < uVar10) {
            uVar10 = uVar10 - 2;
          }
          uVar3 = DAT_803de69a + 2;
          local_88 = 0x43300000;
          uStack_7c = (uint)DAT_803de660;
          local_80 = 0x43300000;
          dVar16 = (double)(FLOAT_803de658 +
                           (f32)(s32)uStack_7c);
          uStack_84 = uVar10;
          iVar6 = FUN_80286718((double)(float)((double)(float)((double)CONCAT44(0x43300000,uVar10) -
                                                              DOUBLE_803e3038) * dVar16));
          local_78 = 0x43300000;
          uStack_74 = uVar3;
          iVar7 = FUN_80286718((double)(float)((double)(float)((double)CONCAT44(0x43300000,uVar3) -
                                                              DOUBLE_803e3038) * dVar16));
          local_70 = 0x43300000;
          uStack_64 = (uint)DAT_803de661;
          local_68 = 0x43300000;
          dVar16 = (double)(FLOAT_803de65c +
                           (f32)(s32)uStack_64);
          uStack_6c = uVar11;
          iVar8 = FUN_80286718((double)(float)((double)(float)((double)CONCAT44(0x43300000,uVar11) -
                                                              DOUBLE_803e3038) * dVar16));
          local_60 = 0x43300000;
          uStack_5c = iVar5;
          iVar5 = FUN_80286718((double)(float)((double)(float)((double)CONCAT44(0x43300000,iVar5) -
                                                              DOUBLE_803e3038) * dVar16));
          local_98 = CONCAT31(CONCAT21(CONCAT11(DAT_803de673,DAT_803de672),DAT_803de671),
                              DAT_803de670);
          local_94 = local_98;
          FUN_8006fd90(iVar6,iVar8,iVar7,iVar5,&local_94);
        }
      }
      DAT_803de696 = CONCAT11(pbVar14[2],*pbVar15);
      pbVar15 = pbVar14 + 5;
      DAT_803de694 = CONCAT11(pbVar14[4],pbVar14[3]);
      DAT_803de698 = DAT_803de694;
      DAT_803de69a = DAT_803de696;
    }
    else if (uVar13 < 0x82) {
      if (uVar13 == 0x20) {
        uVar12 = 6;
      }
      else if (uVar13 < 0x20) {
        if (uVar13 == 10) {
          if (DAT_803de68c == 0) {
            uVar11 = DAT_803de698 + 10;
            uVar10 = (uint)DAT_803de694;
            uStack_5c = (uint)DAT_803de696;
            uVar3 = countLeadingZeros(DAT_803de69a - uStack_5c);
            uVar9 = countLeadingZeros(uVar11 - uVar10);
            if (uVar3 >> 5 == 0 && uVar9 >> 5 == 0) {
              if (1 < uStack_5c) {
                uStack_5c = uStack_5c - 2;
              }
              iVar6 = DAT_803de69a + 2;
              local_60 = 0x43300000;
              uStack_64 = (uint)DAT_803de660;
              local_68 = 0x43300000;
              dVar16 = (double)(FLOAT_803de658 +
                               (f32)(s32)uStack_64);
              iVar5 = FUN_80286718((double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                                    uStack_5c) -
                                                                  DOUBLE_803e3038) * dVar16));
              local_70 = 0x43300000;
              uStack_6c = iVar6;
              iVar6 = FUN_80286718((double)(float)((double)(float)((double)CONCAT44(0x43300000,iVar6
                                                                                   ) -
                                                                  DOUBLE_803e3038) * dVar16));
              local_78 = 0x43300000;
              uStack_7c = (uint)DAT_803de661;
              local_80 = 0x43300000;
              dVar16 = (double)(FLOAT_803de65c +
                               (f32)(s32)uStack_7c);
              uStack_74 = uVar10;
              iVar7 = FUN_80286718((double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                                    uVar10) -
                                                                  DOUBLE_803e3038) * dVar16));
              local_88 = 0x43300000;
              uStack_84 = uVar11;
              iVar8 = FUN_80286718((double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                                    uVar11) -
                                                                  DOUBLE_803e3038) * dVar16));
              local_a0 = CONCAT31(CONCAT21(CONCAT11(DAT_803de673,DAT_803de672),DAT_803de671),
                                  DAT_803de670);
              local_9c = local_a0;
              FUN_8006fd90(iVar5,iVar7,iVar6,iVar8,&local_9c);
            }
          }
          DAT_803de696 = (ushort)DAT_803de688;
          DAT_803de694 = DAT_803de698 + 0xb;
          DAT_803de698 = DAT_803de694;
          DAT_803de69a = DAT_803de696;
        }
        else {
          if ((9 < uVar13) || (uVar13 < 9)) goto LAB_80137674;
          uVar12 = (uint)DAT_803dc878;
          iVar5 = (uint)DAT_803de69a - (DAT_803de69a / uVar12) * uVar12;
          if (iVar5 != 0) {
            uVar12 = uVar12 - iVar5;
          }
        }
      }
      else if (uVar13 < 0x81) {
LAB_80137674:
        uVar12 = FUN_80134c48(uVar4,uVar13);
      }
      else {
        uVar2 = *(undefined4 *)pbVar15;
        pbVar15 = pbVar14 + 5;
        if (DAT_803de68c != 0) {
          local_90 = uVar2;
          local_8c = uVar2;
          FUN_8025c428(1,(byte *)&local_90);
        }
      }
    }
    else if (uVar13 == 0x86) {
      bVar1 = *pbVar15;
      pbVar15 = pbVar14 + 3;
      DAT_803dc878 = CONCAT11(pbVar14[2],bVar1);
    }
    else if (uVar13 < 0x86) {
      if (uVar13 == 0x84) {
        DAT_803de690 = 1;
      }
      else if (uVar13 < 0x84) {
        DAT_803de690 = 0;
      }
      else {
        bVar1 = *pbVar15;
        pbVar15 = pbVar14 + 5;
        if (DAT_803de68c == 0) {
          DAT_803de670 = pbVar14[4];
          DAT_803de671 = pbVar14[3];
          DAT_803de672 = pbVar14[2];
          DAT_803de673 = bVar1;
          FUN_8005d370(uVar4,bVar1,pbVar14[2],pbVar14[3],pbVar14[4]);
        }
      }
    }
    else {
      if (0x87 < uVar13) goto LAB_80137674;
      DAT_803de660 = *pbVar15;
      DAT_803de661 = pbVar14[2];
      pbVar15 = pbVar14 + 3;
    }
    if (((DAT_803de690 != 0) && (0x1f < uVar13)) && (uVar13 < 0x80)) {
      uVar12 = 7;
    }
    uVar13 = DAT_803de69a + uVar12 & 0xffff;
    DAT_803de69a = (ushort)(DAT_803de69a + uVar12);
    local_60 = 0x43300000;
    uStack_64 = (uint)DAT_803de660;
    local_68 = 0x43300000;
    dVar16 = (double)(FLOAT_803de658 + (float)((double)CONCAT44(0x43300000,uStack_64) - dVar17));
    uStack_6c = DAT_803de676 - 0x10 ^ 0x80000000;
    local_70 = 0x43300000;
    pbVar14 = pbVar15;
    uStack_5c = uVar13;
    if ((float)((double)CONCAT44(0x43300000,uStack_6c) - dVar18) <
        (float)((double)(float)((double)CONCAT44(0x43300000,uVar13) - dVar17) * dVar16)) {
      if (DAT_803de68c == 0) {
        uVar9 = DAT_803de698 + 10;
        uVar11 = (uint)DAT_803de694;
        uStack_5c = (uint)DAT_803de696;
        uVar12 = countLeadingZeros(uVar13 - uStack_5c);
        uVar3 = countLeadingZeros(uVar9 - uVar11);
        if (uVar12 >> 5 == 0 && uVar3 >> 5 == 0) {
          if (1 < uStack_5c) {
            uStack_5c = uStack_5c - 2;
          }
          local_60 = 0x43300000;
          iVar5 = FUN_80286718((double)(float)((double)(float)((double)CONCAT44(0x43300000,uStack_5c
                                                                               ) - DOUBLE_803e3038)
                                              * dVar16));
          local_68 = 0x43300000;
          uStack_64 = uVar13 + 2;
          iVar6 = FUN_80286718((double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                                uVar13 + 2) -
                                                              DOUBLE_803e3038) * dVar16));
          local_70 = 0x43300000;
          uStack_74 = (uint)DAT_803de661;
          local_78 = 0x43300000;
          dVar16 = (double)(FLOAT_803de65c +
                           (f32)(s32)uStack_74);
          uStack_6c = uVar11;
          iVar7 = FUN_80286718((double)(float)((double)(float)((double)CONCAT44(0x43300000,uVar11) -
                                                              DOUBLE_803e3038) * dVar16));
          local_80 = 0x43300000;
          uStack_7c = uVar9;
          iVar8 = FUN_80286718((double)(float)((double)(float)((double)CONCAT44(0x43300000,uVar9) -
                                                              DOUBLE_803e3038) * dVar16));
          local_a8 = CONCAT31(CONCAT21(CONCAT11(DAT_803de673,DAT_803de672),DAT_803de671),
                              DAT_803de670);
          local_a4 = local_a8;
          FUN_8006fd90(iVar5,iVar7,iVar6,iVar8,&local_a4);
          uVar13 = uStack_5c;
        }
      }
      uStack_5c = uVar13;
      DAT_803de696 = (ushort)DAT_803de688;
      DAT_803de694 = DAT_803de698 + 0xb;
      DAT_803de698 = DAT_803de694;
      DAT_803de69a = DAT_803de696;
    }
  } while( true );
}

/*
 * --INFO--
 *
 * Function: FUN_8013577c
 * EN v1.0 Address: 0x8013577C
 * EN v1.0 Size: 108b
 * EN v1.1 Address: 0x801378A8
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8013577c(undefined param_1,undefined param_2,undefined param_3,undefined param_4)
{
  undefined *puVar1;
  
  DAT_803de664 = DAT_803de664 + 1;
  if (0xfa < DAT_803de664) {
    return;
  }
  puVar1 = DAT_803dc87c + 1;
  *DAT_803dc87c = 0x81;
  DAT_803dc87c = puVar1;
  puVar1 = DAT_803dc87c + 1;
  *DAT_803dc87c = param_1;
  DAT_803dc87c = puVar1;
  puVar1 = DAT_803dc87c + 1;
  *DAT_803dc87c = param_2;
  DAT_803dc87c = puVar1;
  puVar1 = DAT_803dc87c + 1;
  *DAT_803dc87c = param_3;
  DAT_803dc87c = puVar1;
  puVar1 = DAT_803dc87c + 1;
  *DAT_803dc87c = param_4;
  DAT_803dc87c = puVar1;
  puVar1 = DAT_803dc87c + 1;
  *DAT_803dc87c = 0;
  DAT_803dc87c = puVar1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801357e8
 * EN v1.0 Address: 0x801357E8
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x80137928
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801357e8(void)
{
  DAT_803dc87c = &DAT_803aac78;
  DAT_803de69a = (short)DAT_803de688;
  DAT_803de698 = (short)DAT_803de680;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8013580c
 * EN v1.0 Address: 0x8013580C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80137950
 * EN v1.1 Size: 736b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8013580c(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80135810
 * EN v1.0 Address: 0x80135810
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80137C30
 * EN v1.1 Size: 160b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80135810(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 char *param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80135814
 * EN v1.0 Address: 0x80135814
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80137CD0
 * EN v1.1 Size: 80b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80135814(void)
{
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80135818
 * EN v1.0 Address: 0x80135818
 * EN v1.0 Size: 504b
 * EN v1.1 Address: 0x80137D20
 * EN v1.1 Size: 104b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80135818(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  FUN_8006f764();
  FLOAT_803de658 = FLOAT_803e3048;
  FLOAT_803de65c = FLOAT_803e3048;
  DAT_803de660 = 0;
  DAT_803de661 = 0;
  DAT_803de6a4 = FUN_8005398c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x25d,
                              param_10,param_11,param_12,param_13,param_14,param_15,param_16);
  DAT_803de6a0 = FUN_8005398c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,1,
                              param_10,param_11,param_12,param_13,param_14,param_15,param_16);
  DAT_803de69c = FUN_8005398c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,2,
                              param_10,param_11,param_12,param_13,param_14,param_15,param_16);
  DAT_803dc87c = &DAT_803aac78;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80135a10
 * EN v1.0 Address: 0x80135A10
 * EN v1.0 Size: 360b
 * EN v1.1 Address: 0x80137D88
 * EN v1.1 Size: 384b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80135a10(undefined4 param_1,undefined4 param_2,byte *param_3)
{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  undefined8 uVar13;
  
  uVar13 = FUN_80286838();
  iVar1 = (int)((ulonglong)uVar13 >> 0x20);
  if (DAT_803de6a8 != '\0') {
    iVar10 = 0;
    iVar8 = ((int)uVar13 + 1) * 0x280;
    iVar9 = (int)uVar13 * 0x280;
    do {
      iVar7 = 0;
      iVar6 = iVar1 + iVar9;
      iVar11 = iVar1 + iVar8;
      iVar5 = (iVar11 + 1) * 2;
      iVar4 = iVar11 * 2;
      iVar3 = (iVar6 + 1) * 2;
      iVar2 = iVar6 * 2;
      iVar12 = 4;
      do {
        if ((1 << iVar7 & (uint)*param_3) != 0) {
          *(undefined2 *)(DAT_803de6b0 + iVar2) = 0xc080;
          *(undefined2 *)(DAT_803de6b0 + iVar3) = 0xc080;
          *(undefined2 *)(DAT_803de6b0 + iVar4) = 0xc080;
          *(undefined2 *)(DAT_803de6b0 + iVar5) = 0xc080;
        }
        if ((1 << iVar7 + 1 & (uint)*param_3) != 0) {
          *(undefined2 *)(DAT_803de6b0 + iVar2 + 2) = 0xc080;
          *(undefined2 *)(DAT_803de6b0 + iVar3 + 2) = 0xc080;
          *(undefined2 *)(DAT_803de6b0 + iVar4 + 2) = 0xc080;
          *(undefined2 *)(DAT_803de6b0 + iVar5 + 2) = 0xc080;
        }
        iVar2 = iVar2 + 4;
        iVar3 = iVar3 + 4;
        iVar4 = iVar4 + 4;
        iVar5 = iVar5 + 4;
        iVar7 = iVar7 + 2;
        iVar12 = iVar12 + -1;
      } while (iVar12 != 0);
      FUN_80242114(DAT_803de6b0 + iVar6 * 2,0x10);
      FUN_80242114(DAT_803de6b0 + iVar11 * 2,0x10);
      iVar9 = iVar9 + 0x500;
      iVar8 = iVar8 + 0x500;
      iVar10 = iVar10 + 1;
      param_3 = param_3 + 1;
    } while (iVar10 < 5);
  }
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80135b78
 * EN v1.0 Address: 0x80135B78
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80137F08
 * EN v1.1 Size: 424b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80135b78(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,char *param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80135b7c
 * EN v1.0 Address: 0x80135B7C
 * EN v1.0 Size: 196b
 * EN v1.1 Address: 0x801380B0
 * EN v1.1 Size: 204b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80135b7c(void)
{
  FUN_802430ec(0,FUN_80135c48);
  FUN_802430ec(1,FUN_80135c48);
  FUN_802430ec(2,FUN_80135c48);
  FUN_802430ec(0xb,FUN_80135c48);
  FUN_802430ec(0xd,FUN_80135c48);
  FUN_802430ec(0xf,FUN_80135c48);
  FUN_802430ec(3,FUN_80135c48);
  FUN_802430ec(5,FUN_80135c48);
  FUN_80246a0c(-0x7fc54288,FUN_80135c44,0,0x803ad088,0x1000,0,1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80135c40
 * EN v1.0 Address: 0x80135C40
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8013817C
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80135c40(void)
{
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80135c44
 * EN v1.0 Address: 0x80135C44
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80138180
 * EN v1.1 Size: 2776b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80135c44(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80135c48
 * EN v1.0 Address: 0x80135C48
 * EN v1.0 Size: 60b
 * EN v1.1 Address: 0x80138C58
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80135c48(undefined2 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)
{
  DAT_803de6b4 = param_4;
  DAT_803de6b8 = param_3;
  DAT_803de6bc = param_2;
  DAT_803de6c0 = param_1;
  FUN_80246dcc(-0x7fc54288);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80135c84
 * EN v1.0 Address: 0x80135C84
 * EN v1.0 Size: 24b
 * EN v1.1 Address: 0x80138C90
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80135c84(int param_1,uint param_2)
{
  *(byte *)(*(int *)(param_1 + 0xb8) + 0x58) =
       (byte)((param_2 & 0xff) << 6) & 0x40 | *(byte *)(*(int *)(param_1 + 0xb8) + 0x58) & 0xbf;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80135c9c
 * EN v1.0 Address: 0x80135C9C
 * EN v1.0 Size: 184b
 * EN v1.1 Address: 0x80138CA8
 * EN v1.1 Size: 192b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80135c9c(int param_1,ushort param_2,short param_3)
{
  undefined4 uVar1;
  bool bVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  if ((*(byte *)(iVar3 + 0x58) >> 6 & 1) == 0) {
    if ((*(short *)(param_1 + 0xa0) < 0x30) && (0x28 < *(short *)(param_1 + 0xa0))) {
      uVar1 = 0;
    }
    else {
      bVar2 = FUN_800067f0(param_1,0x10);
      if (bVar2) {
        uVar1 = 0;
      }
      else {
        FUN_80039468(param_1,iVar3 + 0x3a8,param_2,param_3,0xffffffff,0);
        uVar1 = 1;
      }
    }
  }
  else {
    uVar1 = 0;
  }
  return uVar1;
}

/*
 * --INFO--
 *
 * Function: FUN_80135d54
 * EN v1.0 Address: 0x80135D54
 * EN v1.0 Size: 484b
 * EN v1.1 Address: 0x80138D68
 * EN v1.1 Size: 384b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80135d54(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10,int *param_11)
{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined8 uVar4;
  char local_18 [12];
  
  if (*param_11 != 0) {
    uVar4 = ObjLink_DetachChild(param_9,*param_11);
    FUN_80017ac8(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,*param_11);
    *param_11 = 0;
    local_18[0] = -1;
    local_18[1] = 0xff;
    local_18[2] = 0xff;
    iVar1 = *(int *)(param_10 + 0x7a8);
    if (iVar1 != 0) {
      local_18[*(byte *)(param_10 + 0x7bc) >> 6] = '\x01';
    }
    iVar2 = *(int *)(param_10 + 0x7b0);
    if (iVar2 != 0) {
      local_18[*(byte *)(param_10 + 0x7bc) >> 4 & 3] = '\x01';
    }
    iVar3 = *(int *)(param_10 + 0x7b8);
    if (iVar3 != 0) {
      local_18[*(byte *)(param_10 + 0x7bc) >> 2 & 3] = '\x01';
    }
    if (local_18[0] == -1) {
      if (iVar1 == 0) {
        if (iVar2 == 0) {
          if (iVar3 != 0) {
            ObjLink_DetachChild(param_9,iVar3);
            ObjLink_AttachChild(param_9,*(int *)(param_10 + 0x7b8),0);
            *(byte *)(param_10 + 0x7bc) = *(byte *)(param_10 + 0x7bc) & 0xf3;
          }
        }
        else {
          ObjLink_DetachChild(param_9,iVar2);
          ObjLink_AttachChild(param_9,*(int *)(param_10 + 0x7b0),0);
          *(byte *)(param_10 + 0x7bc) = *(byte *)(param_10 + 0x7bc) & 0xcf;
        }
      }
      else {
        ObjLink_DetachChild(param_9,iVar1);
        ObjLink_AttachChild(param_9,*(int *)(param_10 + 0x7a8),0);
        *(byte *)(param_10 + 0x7bc) = *(byte *)(param_10 + 0x7bc) & 0x3f;
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80135f38
 * EN v1.0 Address: 0x80135F38
 * EN v1.0 Size: 984b
 * EN v1.1 Address: 0x80138EE8
 * EN v1.1 Size: 540b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80135f38(int param_1,undefined4 *param_2)
{
  float fVar1;
  float fVar2;
  int *piVar3;
  
  FUN_80017a54(param_1);
  if (*(char *)((int)param_2 + 0x82e) < '\0') {
    piVar3 = (int *)FUN_80017a54(param_1);
    FUN_800178e8((double)FLOAT_803e306c,piVar3,1,-1,0x1a,0x21);
    param_2[0x20c] = FLOAT_803e3070;
    FUN_800178e4((double)FLOAT_803e306c,piVar3,0);
    *(byte *)((int)param_2 + 0x82e) = *(byte *)((int)param_2 + 0x82e) & 0x7f;
    *(byte *)((int)param_2 + 0x82e) = *(byte *)((int)param_2 + 0x82e) & 0xbf | 0x40;
  }
  if ((*(byte *)((int)param_2 + 0x82e) >> 6 & 1) != 0) {
    fVar1 = (float)((double)CONCAT44(0x43300000,(uint)*(byte *)*param_2) - DOUBLE_803e3090) /
            (float)((double)CONCAT44(0x43300000,(uint)((byte *)*param_2)[1]) - DOUBLE_803e3090);
    if (fVar1 <= (float)param_2[0x20c]) {
      if (fVar1 < (float)param_2[0x20c]) {
        param_2[0x20d] = -(FLOAT_803e3074 * FLOAT_803dc074 - (float)param_2[0x20d]);
        param_2[0x20c] = (float)param_2[0x20d] * FLOAT_803dc074 + (float)param_2[0x20c];
        fVar2 = FLOAT_803e306c;
        if ((float)param_2[0x20c] < FLOAT_803e306c) {
          param_2[0x20d] = FLOAT_803e306c;
          param_2[0x20c] = fVar2;
        }
        if ((float)param_2[0x20c] < fVar1) {
          if ((float)param_2[0x20d] <= FLOAT_803e3084) {
            param_2[0x20d] = (float)param_2[0x20d] * FLOAT_803e3080;
          }
          else {
            param_2[0x20d] = FLOAT_803e306c;
            param_2[0x20c] = fVar1;
          }
        }
      }
    }
    else {
      param_2[0x20d] = FLOAT_803e3074 * FLOAT_803dc074 + (float)param_2[0x20d];
      param_2[0x20c] = (float)param_2[0x20d] * FLOAT_803dc074 + (float)param_2[0x20c];
      fVar2 = FLOAT_803e3078;
      if ((float)param_2[0x20c] <= FLOAT_803e3078) {
        if (fVar1 < (float)param_2[0x20c]) {
          if (FLOAT_803e307c <= (float)param_2[0x20d]) {
            param_2[0x20d] = (float)param_2[0x20d] * FLOAT_803e3080;
          }
          else {
            param_2[0x20d] = FLOAT_803e306c;
            param_2[0x20c] = fVar1;
          }
        }
      }
      else {
        param_2[0x20d] = FLOAT_803e306c;
        param_2[0x20c] = fVar2;
      }
    }
    piVar3 = (int *)FUN_80017a54(param_1);
    FUN_800178e4((double)(FLOAT_803e3088 * (float)param_2[0x20c] - FLOAT_803e3078),piVar3,1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80136310
 * EN v1.0 Address: 0x80136310
 * EN v1.0 Size: 524b
 * EN v1.1 Address: 0x80139104
 * EN v1.1 Size: 380b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80136310(int param_1,int *param_2)
{
  float fVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  undefined uVar5;
  
  uVar2 = *(byte *)(*param_2 + 2) / 10;
  if (*(byte *)(param_2 + 0x20b) != uVar2) {
    uVar3 = FUN_80017690(0x3ed);
    if (uVar3 == 0) {
      FUN_80017698(0x3ed,1);
      (**(code **)(*DAT_803dd6d4 + 0x48))(5,param_1,0xffffffff);
      param_2[0x15] = param_2[0x15] | 0x4000;
      param_2[0x20a] = (int)((float)param_2[0x20a] + FLOAT_803e3098);
    }
    param_2[0x20a] = (int)((float)param_2[0x20a] - FLOAT_803dc074);
    fVar1 = (float)param_2[0x20a];
    if (fVar1 <= FLOAT_803e3098) {
      uVar5 = (undefined)uVar2;
      if (fVar1 <= FLOAT_803e306c) {
        *(undefined *)(param_2 + 0x20b) = uVar5;
        FUN_80017a2c(param_1,0,0,0,0,0);
      }
      else {
        if (fVar1 <= FLOAT_803e3070) {
          iVar4 = FUN_80017a54(param_1);
          *(undefined *)(*(int *)(iVar4 + 0x34) + 8) = uVar5;
          fVar1 = (float)param_2[0x20a] / FLOAT_803e3070;
        }
        else {
          fVar1 = FLOAT_803e3078 - (fVar1 - FLOAT_803e3070) / FLOAT_803e3070;
        }
        FUN_80017a2c(param_1,0xff,0xff,0xff,(int)(FLOAT_803e309c * fVar1),1);
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8013651c
 * EN v1.0 Address: 0x8013651C
 * EN v1.0 Size: 28b
 * EN v1.1 Address: 0x80139280
 * EN v1.1 Size: 28b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8013651c(int param_1)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  *(uint *)(iVar1 + 0x54) = *(uint *)(iVar1 + 0x54) | 0x80000000;
  *(float *)(iVar1 + 0x808) = FLOAT_803e3098;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80136538
 * EN v1.0 Address: 0x80136538
 * EN v1.0 Size: 92b
 * EN v1.1 Address: 0x8013929C
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80136538(int param_1)
{
  uint uVar1;
  undefined4 uVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  uVar1 = FUN_80017690(0x4e4);
  if ((uVar1 == 0) ||
     (*(uint *)(iVar3 + 0x54) = *(uint *)(iVar3 + 0x54) | 0x10000,
     (*(uint *)(iVar3 + 0x54) & 0x10) == 0)) {
    uVar2 = 0;
  }
  else {
    uVar2 = 1;
  }
  return uVar2;
}

/*
 * --INFO--
 *
 * Function: FUN_80136594
 * EN v1.0 Address: 0x80136594
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x80139300
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
double FUN_80136594(int param_1)
{
  return (double)*(float *)(*(int *)(param_1 + 0xb8) + 0x14);
}

/*
 * --INFO--
 *
 * Function: FUN_801365a0
 * EN v1.0 Address: 0x801365A0
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x8013930C
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801365a0(int param_1)
{
  return *(undefined4 *)(*(int *)(param_1 + 0xb8) + 0x24);
}

/*
 * --INFO--
 *
 * Function: FUN_801365ac
 * EN v1.0 Address: 0x801365AC
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x80139318
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_801365ac(int param_1)
{
  return (int)*(short *)(*(int *)(param_1 + 0xb8) + 0x414);
}

/*
 * --INFO--
 *
 * Function: FUN_801365b8
 * EN v1.0 Address: 0x801365B8
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x80139324
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_801365b8(int param_1)
{
  return *(int *)(param_1 + 0xb8) + 0x408;
}

/*
 * --INFO--
 *
 * Function: FUN_801365c4
 * EN v1.0 Address: 0x801365C4
 * EN v1.0 Size: 496b
 * EN v1.1 Address: 0x80139330
 * EN v1.1 Size: 444b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801365c4(void)
{
  short sVar1;
  int *piVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  int iVar7;
  double extraout_f1;
  double dVar8;
  double in_f30;
  double dVar9;
  double in_f31;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar10;
  int local_48 [12];
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  uVar10 = FUN_80286834();
  dVar9 = extraout_f1;
  piVar2 = ObjGroup_GetObjects(3,local_48);
  dVar9 = (double)(float)(dVar9 * dVar9);
  for (iVar7 = 0; iVar7 < local_48[0]; iVar7 = iVar7 + 1) {
    iVar3 = FUN_801113c0(*piVar2);
    if (iVar3 == 0) {
      dVar8 = FUN_8014cbcc(*piVar2);
    }
    else {
      dVar8 = (double)(**(code **)(*DAT_803dd738 + 0x60))(*piVar2);
    }
    iVar3 = *(int *)(*piVar2 + 0x4c);
    if ((int)*(short *)(iVar3 + 0x18) == 0xffffffff) {
      uVar5 = 0;
    }
    else {
      uVar5 = FUN_80017690((int)*(short *)(iVar3 + 0x18));
    }
    if ((int)*(short *)(iVar3 + 0x1a) == 0xffffffff) {
      uVar6 = 1;
    }
    else {
      uVar6 = FUN_80017690((int)*(short *)(iVar3 + 0x1a));
    }
    uVar4 = ObjGroup_ContainsObject(*piVar2,0x31);
    if ((((((uVar4 == 0) && ((double)FLOAT_803e306c < dVar8)) && (uVar5 == 0)) &&
         ((uVar6 != 0 && (*(short *)(*piVar2 + 0x46) != 0x851)))) &&
        (iVar3 = (**(code **)(*DAT_803dd72c + 0x68))(*(undefined4 *)(iVar3 + 0x14)), iVar3 != 0)) &&
       ((((int)uVar10 != 0 ||
         (((sVar1 = *(short *)(*piVar2 + 0x46), sVar1 != 0x3fe && (sVar1 != 0x4d7)) &&
          ((sVar1 != 0x27c && (sVar1 != 0x251)))))) &&
        (dVar8 = FUN_80017714((float *)((int)((ulonglong)uVar10 >> 0x20) + 0x18),
                              (float *)(*piVar2 + 0x18)), dVar8 < dVar9)))) {
      dVar9 = dVar8;
    }
    piVar2 = piVar2 + 1;
  }
  FUN_80286880();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801367b4
 * EN v1.0 Address: 0x801367B4
 * EN v1.0 Size: 188b
 * EN v1.1 Address: 0x801394EC
 * EN v1.1 Size: 252b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801367b4(undefined2 *param_1,int param_2)
{
  bool bVar1;
  char cVar2;
  undefined2 local_28;
  undefined2 local_26;
  undefined2 local_24;
  float local_20;
  float local_1c;
  float local_18;
  float local_14;
  
  cVar2 = '\x14';
  if ((*(uint *)(param_2 + 0x54) & 0x1800) != 0) {
    local_1c = *(float *)(param_2 + 0x408) - *(float *)(param_1 + 0xc);
    local_18 = *(float *)(param_2 + 0x40c) - *(float *)(param_1 + 0xe);
    local_14 = *(float *)(param_2 + 0x410) - *(float *)(param_1 + 0x10);
    local_20 = FLOAT_803e3078;
    local_28 = *param_1;
    local_26 = param_1[1];
    local_24 = param_1[2];
    if ((*(uint *)(param_2 + 0x54) & 0x800) == 0) {
      while (bVar1 = cVar2 != '\0', cVar2 = cVar2 + -1, bVar1) {
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x533,&local_28,2,0xffffffff,0);
      }
      *(uint *)(param_2 + 0x54) = *(uint *)(param_2 + 0x54) & 0xffffefff;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80136870
 * EN v1.0 Address: 0x80136870
 * EN v1.0 Size: 304b
 * EN v1.1 Address: 0x801395E8
 * EN v1.1 Size: 316b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80136870(void)
{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  undefined8 uVar9;
  
  uVar9 = FUN_8028683c();
  iVar1 = (int)((ulonglong)uVar9 >> 0x20);
  dVar7 = (double)FLOAT_803e30a8;
  iVar4 = 0;
  iVar3 = 0;
  iVar2 = iVar1;
  dVar8 = dVar7;
  for (iVar5 = 0; iVar5 < (int)(uint)*(byte *)(iVar1 + 0x798); iVar5 = iVar5 + 1) {
    if ((int)*(char *)(iVar2 + 0x74d) == (int)uVar9) {
      dVar6 = FUN_80017708((float *)(*(int *)(iVar1 + 4) + 0x18),
                           (float *)(*(int *)(iVar2 + 0x748) + 0x18));
      if (*(char *)(iVar2 + 0x74c) == '\x01') {
        if (dVar6 < dVar8) {
          iVar4 = *(int *)(iVar2 + 0x748);
          dVar8 = dVar6;
        }
      }
      else if (dVar6 < dVar7) {
        iVar3 = *(int *)(iVar2 + 0x748);
        dVar7 = dVar6;
      }
    }
    iVar2 = iVar2 + 8;
  }
  if (iVar4 == 0) {
    if (iVar3 == 0) goto LAB_801396fc;
    *(int *)(iVar1 + 0x24) = iVar3;
  }
  else {
    *(int *)(iVar1 + 0x24) = iVar4;
  }
  iVar2 = *(int *)(iVar1 + 0x24) + 0x18;
  if (*(int *)(iVar1 + 0x28) != iVar2) {
    *(int *)(iVar1 + 0x28) = iVar2;
    *(uint *)(iVar1 + 0x54) = *(uint *)(iVar1 + 0x54) & 0xfffffbff;
    *(undefined2 *)(iVar1 + 0xd2) = 0;
  }
  *(undefined *)(iVar1 + 10) = 0;
LAB_801396fc:
  FUN_80286888();
  return;
}

/* ===== EN v1.0 retargeted leaves ========================================= */

extern u32 lbl_803DD938;
extern u8  lbl_803DD988;
extern u32 lbl_803DD9B8;
extern u32 lbl_803DD9BC;
extern u8  lbl_803DD9AB;
extern u8  lbl_803DD993;

/* 4-byte and 8-byte trivial leaves. */
void dll_3F_frameEnd_nop(void) {}
void Credits_render(void) {}
void Credits_frameEnd(void) {}
void WarpstoneUI_frameEnd(void) {}
void reportAllocFail(void) {}
int  dll_3F_frameStart_ret_0(void) { return 0; }
u8   shouldShowCredits(void) { return lbl_803DD993; }

/* EN v1.0 0x801334D4  size: 12b  u16-narrow getter for lbl_803DD938. */
u16 getMinimapY(void) { return (u16)lbl_803DD938; }

/* EN v1.0 0x801344F0  size: 12b  u8 setter writing arg low byte to
 * lbl_803DD988. */
#pragma peephole off
void WarpstoneUI_setState(int val) { lbl_803DD988 = (u8)val; }
#pragma peephole reset

/* EN v1.0 0x80135814  size: 12b  Two-word setter for state pair. */
void fn_80135814(u32 a, u32 b) { lbl_803DD9BC = a; lbl_803DD9B8 = b; }

/* EN v1.0 0x801368D4  size: 12b  Clear lbl_803DD9AB to 0. */
void titleScreenFn_801368d4(void) { lbl_803DD9AB = 0; }

/* EN v1.0 0x80138F78  size: 12b  obj->_b8->_14 (f32). */
f32 fn_80138F78(u8* obj) { return *(f32*)(*(u8**)(obj + 0xb8) + 0x14); }
/* EN v1.0 0x80138F84  size: 12b  obj->_b8->_24 (u32). */
u32 fn_80138F84(u8* obj) { return *(u32*)(*(u8**)(obj + 0xb8) + 0x24); }
/* EN v1.0 0x80138F90  size: 12b  obj->_b8->_414 (s16). */
s16 fn_80138F90(u8* obj) { return *(s16*)(*(u8**)(obj + 0xb8) + 0x414); }
/* EN v1.0 0x80138F9C  size: 12b  Returns Tricky's queued path particle position. */
void* trickyGetQueuedPathParticlePos(u8* obj) { return (void*)(*(u8**)(obj + 0xb8) + 0x408); }

/* EN v1.0 0x80135BC4  size: 8b   titlescreen_getExtraSize -> 56. */
int titlescreen_getExtraSize(void) { return 56; }

/* EN v1.0 0x80135CC4  size: 4b   titlescreen_hitDetect (empty stub). */
void titlescreen_hitDetect(void) {}

/* EN v1.0 0x80135BCC  size: 36b  titlescreen_getObjectTypeId: returns 74 if
 * obj->_46 (s16) is in [1917, 1920], else returns 0. */
int titlescreen_getObjectTypeId(u8* obj)
{
    s16 v = *(s16*)(obj + 0x46);
    if (v >= 1917 && v < 1921) return 74;
    return 0;
}

extern void titlescreen_free(u8* obj);
extern void titlescreen_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
extern void titlescreen_update(u8 *obj);
extern void titlescreen_init(u8* obj, u8* p);
extern void titlescreen_release(void);
extern void titlescreen_initialise(void);

ObjectDescriptor10WithPadding gTitleScreenObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
        (ObjectDescriptorCallback)titlescreen_initialise,
        (ObjectDescriptorCallback)titlescreen_release,
        0,
        (ObjectDescriptorCallback)titlescreen_init,
        (ObjectDescriptorCallback)titlescreen_update,
        (ObjectDescriptorCallback)titlescreen_hitDetect,
        (ObjectDescriptorCallback)titlescreen_render,
        (ObjectDescriptorCallback)titlescreen_free,
        (ObjectDescriptorCallback)titlescreen_getObjectTypeId,
        titlescreen_getExtraSize,
    },
    0,
};

extern void* lbl_803DD9D4;
extern void* lbl_803A9F98[0x13];
extern u8    lbl_803DD992;
extern f32   lbl_803DD968;
extern f32   lbl_803E22A8;
extern u8    lbl_803DD970;
extern void* lbl_803DD974;
extern void* lbl_803DD96C;
extern void* gameTextGet(s32);
extern void* textureLoadAsset(s32);
extern void  textureFree(void*);

/* EN v1.0 0x801368E0  size: 124b  titlescreen_release: free the main
 * buffer at lbl_803DD9D4 and walk the 19-slot table at lbl_803A9F98
 * releasing each non-null entry, then clear the busy byte at
 * lbl_803DD992. */
#pragma scheduling off
#pragma peephole off
void titlescreen_release(void)
{
    register void** p;
    int i;
    textureFree(lbl_803DD9D4);
    lbl_803DD9D4 = NULL;
    i = 0;
    p = lbl_803A9F98;
    do {
        if (*p != NULL) {
            textureFree(*p);
            *p = NULL;
        }
        p++;
        i++;
    } while (i < 19);
    lbl_803DD992 = 0;
}
#pragma peephole reset
#pragma scheduling reset

extern s8    lbl_803DBC08;
extern s8    lbl_803DBC09;
extern u8    lbl_803DD990;
extern u8    lbl_803DD991;
extern u8    lbl_803DC968;
extern f32   lbl_803DD9D0;
extern f32   lbl_803DD9CC;
extern f32   lbl_803DD9C4;
extern f32   lbl_803DD9B4;
extern f32   lbl_803DD9B0;
extern int   lbl_803DD9AC;
extern f32   lbl_803E2318;
extern f32   lbl_803E22F8;
extern u8    lbl_803A9FE4[0x34];
extern s16   lbl_8031CDE8[];
extern void  PSMTXIdentity(void*);

/* EN v1.0 0x8013695C  size: 228b  titlescreen_initialise: reset state
 * bytes, load the main texture (asset 0x647 or 0xC5 depending on
 * lbl_803DC968), identity the matrix, then load the 19-entry texture
 * table from the id list at lbl_8031CDE8 into lbl_803A9F98. */
#pragma scheduling off
#pragma peephole off
void titlescreen_initialise(void)
{
    int i;
    lbl_803DBC08 = -1;
    lbl_803DD990 = 0;
    lbl_803DBC09 = -1;
    lbl_803DD991 = 0;
    if (lbl_803DC968 != 0) {
        lbl_803DD9D4 = textureLoadAsset(0x647);
    } else {
        lbl_803DD9D4 = textureLoadAsset(0xC5);
    }
    lbl_803DD9D0 = lbl_803E2318;
    lbl_803DD9CC = lbl_803E2318;
    PSMTXIdentity(lbl_803A9FE4);
    for (i = 0; i < 19; i++) {
        lbl_803A9F98[i] = textureLoadAsset(lbl_8031CDE8[i]);
    }
    lbl_803DD9C4 = lbl_803E22F8;
    lbl_803DD992 = 0;
    lbl_803DD9AC = 0;
    lbl_803DD9B4 = lbl_803E2318;
    lbl_803DD9B0 = lbl_803E2318;
    lbl_803DD9AB = 1;
}
#pragma peephole reset
#pragma scheduling reset

extern u8    lbl_803DD9AA;
extern int   lbl_803DD9A4;
extern int  *gObjectTriggerInterface;
extern void  objRenderFn_8003b8f4(f32);

/* EN v1.0 0x80135C2C  size: 152b  titlescreen_render: when visible and
 * ready, render via objRenderFn; once the credits flag fires, set the
 * one-shot trigger 0x57 and release the attract-mode movie buffers. */
#pragma scheduling off
#pragma peephole off
void titlescreen_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v == 0) return;
    if (lbl_803DD9AB == 0) return;
    objRenderFn_8003b8f4(lbl_803E2318);
    if (lbl_803DD993 == 0) return;
    if (lbl_803DD9AA != 0) return;
    GameBit_Set(0xDF6, 1);
    lbl_803DD9AA = 1;
    ((void (*)(int, int, int, int))((void **)*gObjectTriggerInterface)[0x50 / 4])(0x57, 0, 0, 0);
    n_attractmode_releaseMovieBuffers();
    lbl_803DD9A4 = 0;
}
#pragma peephole reset
#pragma scheduling reset

typedef struct TitleAnimMoves {
    f32 moves[8];
} TitleAnimMoves;
extern TitleAnimMoves lbl_8031CE10[];
extern void  ObjAnim_SetCurrentMove(void *obj, int n, f32 v, int m);
extern void  ObjModel_SetRenderCallback(int* model, void* cb);
extern void  AttractMovie_DrawTextureCallback(void);

/* EN v1.0 0x801367A8  size: 252b  titlescreen_init: seed the object's
 * state from its descriptor id (obj->_46), pick the anim move and blend
 * float per id range, and for the attract id install the movie draw
 * callback. */
#pragma scheduling off
#pragma peephole off
void titlescreen_init(u8* obj, u8* p)
{
    u8* a = *(u8**)(obj + 0xb8);
    s16 v;
    *(u8*)(a + 0x30) = 0;
    *(s16*)(obj + 0) = (s16)((s8)p[0x18] << 8);
    v = *(s16*)(obj + 0x46);
    if (v >= 0x77d && v < 0x781) {
        *(s8*)(a + 0x31) = (s8)(v - 0x77d);
        *(f32*)(a + 0x34) = lbl_8031CE10[*(s16*)(obj + 0x46) - 0x77d].moves[0];
        ObjAnim_SetCurrentMove(obj, 0, lbl_803E22F8, 0);
    } else {
        *(f32*)(a + 0x34) = lbl_803E22F8;
        *(s8*)(a + 0x31) = -2;
        v = *(s16*)(obj + 0x46);
        if (v == 0x78a) {
            ObjAnim_SetCurrentMove(obj, 1, lbl_803E22F8, 0);
        } else if (v == 0x781) {
            ObjAnim_SetCurrentMove(obj, 0, lbl_803E2318, 0);
            ObjModel_SetRenderCallback(*(int**)(*(int**)(obj + 0x7c)),
                                       (void*)AttractMovie_DrawTextureCallback);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

extern int  *gPartfxInterface;
extern f32   lbl_803E23E8;

/* EN v1.0 0x80139164  size: 252b  Tricky_emitQueuedPathParticles: when b->_54 carries the
 * spawn flag, build a particle descriptor on the stack from a's heading
 * and the delta to b's position, then emit it 20 times via the partfx
 * interface and clear the flag. */
#pragma scheduling off
#pragma peephole off
void Tricky_emitQueuedPathParticles(u8* a, u8* b)
{
    struct {
        s16 hx, hy, hz;
        f32 fk;
        f32 dx, dy, dz;
    } stk;
    u8 i;
    u32 flags = *(u32*)(b + 0x54);
    if ((flags & 0x1800) == 0) return;
    stk.dx = *(f32*)(b + 0x408) - *(f32*)(a + 0x18);
    stk.dy = *(f32*)(b + 0x40c) - *(f32*)(a + 0x1c);
    stk.dz = *(f32*)(b + 0x410) - *(f32*)(a + 0x20);
    stk.fk = lbl_803E23E8;
    stk.hx = *(s16*)(a + 0);
    stk.hy = *(s16*)(a + 2);
    stk.hz = *(s16*)(a + 4);
    if ((flags & 0x800) != 0) return;
    i = 0x14;
    while (i-- != 0) {
        ((void (*)(int, int, void *, int, int, int))(*(int *)(*(int *)gPartfxInterface + 8)))(
            (int)a, 0x533, &stk, 2, -1, 0);
    }
    *(u32*)(b + 0x54) = *(u32*)(b + 0x54) & ~0x1000;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int trickySelectQueuedCommandTarget(u8* state, int commandType)
{
    extern f32 getXZDistance(f32* a, f32* b);
    extern f32 lbl_803E2418;
    f32 bestPriorityDist;
    f32 bestFallbackDist;
    u8* entry;
    int i;
    u8* bestPriorityTarget;
    u8* bestFallbackTarget;

    bestPriorityDist = lbl_803E2418;
    bestPriorityTarget = NULL;
    bestFallbackDist = bestPriorityDist;
    bestFallbackTarget = NULL;

    for (i = 0, entry = state; i < state[0x798]; i++) {
        if (*(s8*)(entry + 0x74d) == commandType) {
            f32 dist = getXZDistance((f32*)(*(u8**)(state + 4) + 0x18), (f32*)(*(u8**)(entry + 0x748) + 0x18));

            if (*(s8*)(entry + 0x74c) == 1) {
                if (dist < bestPriorityDist) {
                    bestPriorityDist = dist;
                    bestPriorityTarget = *(u8**)(entry + 0x748);
                }
            } else if (dist < bestFallbackDist) {
                bestFallbackDist = dist;
                bestFallbackTarget = *(u8**)(entry + 0x748);
            }
        }
        entry += 8;
    }

    if (bestPriorityTarget != NULL) {
        *(u8**)(state + 0x24) = bestPriorityTarget;
    } else {
        if (bestFallbackTarget == NULL) {
            return 0;
        }
        *(u8**)(state + 0x24) = bestFallbackTarget;
    }

    {
        u8* targetPos = *(u8**)(state + 0x24) + 0x18;
        u32 pathMask = 0xfffffbff;
        if (*(u8**)(state + 0x28) != targetPos) {
            *(u8**)(state + 0x28) = targetPos;
            *(u32*)(state + 0x54) = *(u32*)(state + 0x54) & pathMask;
            *(u16*)(state + 0xd2) = 0;
        }
    }

    state[0xa] = 0;
    return 1;
}
#pragma peephole reset
#pragma scheduling reset

/* EN v1.0 0x80134388  size: 68b  Acquire two buffers and prime the
 * float at lbl_803DD968. */
#pragma scheduling off
#pragma peephole off
void Credits_initialise(void)
{
    lbl_803DD974 = textureLoadAsset(0xC5);
    lbl_803DD96C = gameTextGet(0x1FD);
    lbl_803DD970 = 0;
    lbl_803DD968 = lbl_803E22A8;
}
#pragma peephole reset
#pragma scheduling reset

/* EN v1.0 0x80138F14  size: 100b  GameBit-gated bit toggle on
 * obj->_b8->_54: requires GameBit_Get(0x4E4); sets bit 0x10000 then
 * checks bit 0x10. Returns 1 only when the post-OR check passes. */
#pragma peephole off
int trickyFn_80138f14(u8* obj)
{
    u8* b = *(u8**)(obj + 0xb8);
    if ((u32)GameBit_Get(0x4E4) != 0u) {
        *(u32*)(b + 0x54) |= 0x10000;
        if ((*(u32*)(b + 0x54) & 0x10) != 0u) {
            return 1;
        }
    }
    return 0;
}
#pragma peephole reset

extern u8    lbl_803A9FE4[0x34];
extern f32   lbl_803E22F8;
extern f32   lbl_803E2344;
extern f32   lbl_803E2348;
extern f32   lbl_803E234C;
extern f32   lbl_803E2350;
extern f32   lbl_803E2318;
extern f32   lbl_803DD9C8;
extern f32   lbl_803DD9B4;
extern f32   lbl_803DD9B0;
extern void  PSMTXTrans(void*, f32, f32, f32);

extern void* lbl_803DBBC8[2];
extern void  Obj_FreeObject(void*);
extern void* minimapTexture;
extern void* lbl_803DD940;

extern f32   lbl_803E23B8;
extern f32   lbl_803DD9D8;
extern f32   lbl_803DD9DC;
extern u8    lbl_803DD9E0;
extern u8    lbl_803DD9E1;
extern void* lbl_803DDA1C;
extern void* lbl_803DDA20;
extern void* lbl_803DDA24;
extern void* debugLogEnd;
extern u8    debugLogBuffer[0x1100];
extern void  getScreenResolution(void);
extern int   vsprintf(char *s, const char *format, va_list arg);

/* EN v1.0 0x80137998  size: 104b  Title-screen system init. Calls
 * getScreenResolution, primes the two float counters, clears two state bytes,
 * acquires three sized buffers (605/1/2 bytes) and primes the
 * debugLogEnd cursor to the start of the 0x1100-byte arena. */
#pragma scheduling off
#pragma peephole off
void fn_80137998(void)
{
    getScreenResolution();
    lbl_803DD9D8 = lbl_803E23B8;
    lbl_803DD9DC = lbl_803E23B8;
    lbl_803DD9E0 = 0;
    lbl_803DD9E1 = 0;
    lbl_803DDA24 = textureLoadAsset(0x25D);
    lbl_803DDA20 = textureLoadAsset(1);
    lbl_803DDA1C = textureLoadAsset(2);
    debugLogEnd = debugLogBuffer;
}
#pragma peephole reset
#pragma scheduling reset

/* EN v1.0 0x80137520  size: 128b  Emit a SetColor record (tag 0x81 +
 * 4 RGBA bytes + 0 terminator) into the debug log; aborts when the
 * record counter at lbl_803DD9E4 has already exceeded 0xFA. */
extern int lbl_803DD9E4;
#pragma scheduling off
void debugPrintSetColor(u8 r, u8 g, u8 b, u8 a)
{
    int n;
    u8* p;
    n = lbl_803DD9E4 + 1;
    lbl_803DD9E4 = n;
    if (n > 0xfa) return;
    p = (u8*)debugLogEnd; debugLogEnd = p + 1; *p = 0x81;
    p = (u8*)debugLogEnd; debugLogEnd = p + 1; *p = r;
    p = (u8*)debugLogEnd; debugLogEnd = p + 1; *p = g;
    p = (u8*)debugLogEnd; debugLogEnd = p + 1; *p = b;
    p = (u8*)debugLogEnd; debugLogEnd = p + 1; *p = a;
    p = (u8*)debugLogEnd; debugLogEnd = p + 1; *p = 0;
}
#pragma scheduling reset

extern int  Sfx_IsPlayingFromObjectChannel(u8*, int);
extern void objAudioFn_800393f8(u8*, u8*, int, int, int, int);

/* EN v1.0 0x80138920  size: 192b  Drop-anim trigger guard. Returns 1
 * (and dispatches the drop anim via objAudioFn_800393f8) only when:
 *   - bit 0x40 of obj->_b8->_58 is clear,
 *   - the target halfword obj->_a0 is OUTSIDE the [41, 47] window,
 *   - Sfx_IsPlayingFromObjectChannel(obj, 16) returns 0. */
#pragma scheduling off
#pragma peephole off
int fn_80138920(u8* obj, int arg1, int arg2)
{
    u8* b = *(u8**)(obj + 0xb8);
    s16 v;
    if ((u32)((b[0x58] >> 6) & 1) != 0u) return 0;
    v = *(s16*)(obj + 0xa0);
    if (v < 48) {
        if (v >= 41) {
            return 0;
        }
    }
    if (Sfx_IsPlayingFromObjectChannel(obj, 16) != 0) return 0;
    objAudioFn_800393f8(obj, b + 936, arg1, arg2, -1, 0);
    return 1;
}
#pragma peephole reset
#pragma scheduling reset

extern int Obj_AllocObjectSetup(int a, int b);
extern int Obj_SetupObject(int obj, int b, int c, int d, int e);
extern f32 lbl_803E2208;
extern f32 lbl_803E2284;
extern f32 lbl_803E2288;
extern f32 lbl_803E228C;
extern f32 lbl_803E2290;

#pragma dont_inline on
#pragma scheduling off
#pragma peephole off
void fn_80133818(void)
{
    f32 e;
    f32 d;
    f32 c;
    f32 b;
    f32 a;
    u8 i;

    i = 0;
    a = lbl_803E2284;
    b = lbl_803E2288;
    c = lbl_803E2208;
    d = lbl_803E228C;
    e = lbl_803E2290;
    for (; i < 2; i++) {
        lbl_803DBBC8[i] = (void *)Obj_SetupObject(Obj_AllocObjectSetup(32, 2010 + i), 4, -1, -1, 0);
        *(f32 *)((char *)lbl_803DBBC8[i] + 0xc) = a;
        *(f32 *)((char *)lbl_803DBBC8[i] + 0x10) = b;
        *(f32 *)((char *)lbl_803DBBC8[i] + 0xc) = c;
        *(f32 *)((char *)lbl_803DBBC8[i] + 0x10) = c;
        *(f32 *)((char *)lbl_803DBBC8[i] + 0x14) = d;
        *(u16 *)lbl_803DBBC8[i] = 2000;
        *(u16 *)((char *)lbl_803DBBC8[i] + 2) = 0;
        *(f32 *)((char *)lbl_803DBBC8[i] + 8) = e;
    }
}
#pragma peephole reset
#pragma scheduling reset
#pragma dont_inline reset

extern u8 gameTimerIsRunning(void);
extern void gameTimerRun(void *obj);
extern int sprintf(char *buf, const char *fmt, ...);
extern f32 lbl_803E22A0;
__declspec(section ".sdata") extern char lbl_803DBBF0[];

#pragma scheduling off
#pragma peephole off
void fn_80133F70(void *obj)
{
    char buf[12];
    f32 threshold;
    int a;
    int b;
    int c;
    void *player;
    void *nearest;

    threshold = lbl_803E22A0;
    a = 0;
    b = 0;
    c = 0;
    if (gameTimerIsRunning()) {
        gameTimerRun(obj);
    }
    player = (void *)Obj_GetPlayerObject();
    nearest = (void *)ObjGroup_FindNearestObject(9, player, &threshold);
    if (nearest != NULL) {
        ((void (*)(void *, int *, int *, int *))(*(void ***)*(void **)((char *)nearest + 0x68))[21])(nearest, &a, &b, &c);
    }
    b = c - (b - a);
    if (b < 0) {
        b = 0;
    }
    sprintf(buf, lbl_803DBBF0, b);
}
#pragma peephole reset
#pragma scheduling reset

extern void viewFn_80129cbc(f32 a, f32 b, f32 c);
extern void viewFn_80129c74(void);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void objRender(int a, int b, int c, int d, void *obj, int f);
extern int *Obj_GetActiveModel(void *obj);
extern u8 lbl_803DD92A;
extern int lbl_803DD934;
extern f32 lbl_803E2278;
extern f32 lbl_803E227C;
extern f32 lbl_803E2280;

#pragma scheduling off
#pragma peephole off
void fn_80133718(void)
{
    u8 count;
    u8 i;
    int b;
    int *model;

    count = 2;
    viewFn_80129cbc(lbl_803E227C, lbl_803E2278, lbl_803E2280);
    b = (lbl_803DD92A >> 3) & 1;
    if (b != 0) {
        if ((s8) * (u8 *)((char *)lbl_803DBBC8[1] + 173) == 0) {
            Sfx_PlayFromObject(0, 1009);
        }
    }
    *(s8 *)((char *)lbl_803DBBC8[1] + 173) = (s8)b;
    if ((u32)lbl_803DD934 == 0) {
        count = 1;
    }
    for (i = 0; i < count; i++) {
        objRender(0, 0, 0, 0, lbl_803DBBC8[i], 1);
        model = Obj_GetActiveModel(lbl_803DBBC8[i]);
        *(u16 *)((char *)model + 24) = (u16)(*(u16 *)((char *)model + 24) & ~0x8);
        *(u8 *)((char *)lbl_803DBBC8[i] + 55) = 255;
    }
    viewFn_80129c74();
}
#pragma peephole reset
#pragma scheduling reset

/* Variadic debug logger: append formatted text while the debug arena has room. */
#pragma peephole off
#pragma scheduling off
void debugPrintf(char *fmt, ...)
{
    va_list args;

    if ((int)((u8 *)debugLogEnd - debugLogBuffer) <= 0x1000) {
        va_start(args, fmt);
        vsprintf(debugLogEnd, fmt, args);
    }
}
#pragma peephole reset
#pragma scheduling reset

/* Variadic debug-print sink: retail keeps only the ABI varargs spill frame. */
void fn_80137948(char *fmt, ...) {}

/* EN v1.0 0x80133EA4  size: 156b  Two-step shutdown helper. Releases
 * the buffers at minimapTexture and lbl_803DD940 (the first only if
 * non-null), then walks the 2-slot live-objects table at lbl_803DBBC8
 * tearing down each non-null entry via Obj_FreeObject. Both buffer
 * pointers are zeroed at the end. */
void Minimap_release(void)
{
    u8 i;
    void** slots;
    if (minimapTexture != NULL) textureFree(minimapTexture);
    textureFree(lbl_803DD940);
    slots = lbl_803DBBC8;
    i = 0;
    while ((u32)i < 2) {
        if (slots[i] != NULL) {
            Obj_FreeObject(slots[i]);
            slots[i] = NULL;
        }
        i++;
    }
    minimapTexture = NULL;
    lbl_803DD940 = NULL;
}

/* EN v1.0 0x80135820  size: 136b  Set up the title-screen translation
 * matrix at lbl_803A9FE4 and derive the three normalized cursor
 * positions from the supplied (a, b) coordinates. */
#pragma scheduling off
#pragma peephole off
void titleScreenPositionElements(f32 a, f32 b)
{
    PSMTXTrans(lbl_803A9FE4, a, b, lbl_803E22F8);
    lbl_803DD9C8 = (lbl_803E2344 - b) / lbl_803E2348;
    lbl_803DD9B4 = (a - lbl_803E234C) / lbl_803E2350;
    lbl_803DD9B0 = lbl_803E2318 - lbl_803DD9C8;
}
#pragma peephole reset
#pragma scheduling reset

extern void* lbl_803DD960;
extern void* lbl_803DD974;
extern void* lbl_803DD96C;
extern u8    lbl_803DD970;
/* lbl_803DD940 declared later as void* */
extern u8    lbl_803DD990;
extern u8    lbl_803DD991;
extern s8    lbl_803DBC08;
extern s8    lbl_803DBC09;
extern f32   lbl_803E2408;

/* EN v1.0 0x80133F40  size: 48b  Acquire a 0xBE5-byte buffer via
 * textureLoadAsset into lbl_803DD940; reset frame counter at lbl_803DD938. */
#pragma scheduling off
#pragma peephole off
void Minimap_initialise(void)
{
    lbl_803DD940 = textureLoadAsset(0xBE5);
    lbl_803DD938 = 340;
}
#pragma peephole reset
#pragma scheduling reset

/* EN v1.0 0x8013404C  size: 36b  Release the buffer at lbl_803DD960
 * via textureFree. */
void dll_3F_release(void)
{
    textureFree(lbl_803DD960);
}

/* EN v1.0 0x80134070  size: 40b  Acquire 0x47A-byte buffer into
 * lbl_803DD960. */
#pragma scheduling off
#pragma peephole off
void dll_3F_initialise(void)
{
    lbl_803DD960 = textureLoadAsset(0x47A);
}
#pragma peephole reset
#pragma scheduling reset

/* EN v1.0 0x80134364  size: 36b  Release lbl_803DD974 buffer. */
void Credits_release(void)
{
    textureFree(lbl_803DD974);
}

/* EN v1.0 0x801368A4  size: 32b  Two-byte state push: if arg differs
 * from lbl_803DD991, save old to lbl_803DBC09 and set new. */
void titleScreenFn_801368a4(s8 arg)
{
    u8 cur = lbl_803DD991;
    if (arg == (s8)cur) return;
    lbl_803DBC09 = cur;
    lbl_803DD991 = arg;
}

/* EN v1.0 0x801368C4  size: 16b  Two-byte state push (no equality
 * check): copy lbl_803DD990 to lbl_803DBC08 and write new value. */
void titleScreenFn_801368c4(u8 arg)
{
    lbl_803DBC08 = lbl_803DD990;
    lbl_803DD990 = arg;
}

/* EN v1.0 0x80138EF8  size: 28b  Set bit 0x80000000 of obj->_b8->_54
 * and store lbl_803E2408 into obj->_b8->_808. */
void trickyImpress(u8* obj)
{
    u8* b = *(u8**)(obj + 0xb8);
    *(u32*)(b + 0x54) |= 0x80000000;
    *(f32*)(b + 0x808) = lbl_803E2408;
}

extern void* lbl_803DD984;
extern void* lbl_803DD980;
extern void* minimapTexture;
extern void* lbl_803DD92C;
extern f32   lbl_803DD97C;
extern f32   lbl_803E22E0;
extern u8    lbl_803DD993;
extern u8    lbl_803DD9AA;
extern u16   lbl_803DD994;
extern u16   lbl_803DD996;
extern u16   lbl_803DD998;
extern s16   lbl_803DD9A8;
extern int   getCurUiDll(void);

/* EN v1.0 0x80134808  size: 44b  Release two buffer slots in sequence:
 * textureFree(lbl_803DD984) then textureFree(lbl_803DD980). */
void WarpstoneUI_release(void)
{
    textureFree(lbl_803DD984);
    textureFree(lbl_803DD980);
}

/* EN v1.0 0x801347A4  size: 100b  Per-frame integrator with clamp.
 * Adds (or subtracts, when lbl_803DD988 != 0) lbl_803E22D8*timeDelta
 * to lbl_803DD97C, then clamps to [lbl_803E22E0, lbl_803E22DC]. */
extern f32 lbl_803E22D8;
extern f32 lbl_803E22DC;
extern f32 timeDelta;
#pragma scheduling off
int WarpstoneUI_frameStart(void)
{
    f32 v;
    if (lbl_803DD988 == 0) {
        lbl_803DD97C = lbl_803DD97C - (lbl_803E22D8 * timeDelta);
    } else {
        lbl_803DD97C = lbl_803DD97C + (lbl_803E22D8 * timeDelta);
    }
    v = lbl_803DD97C;
    if (lbl_803E22DC < v) {
        lbl_803DD97C = lbl_803E22DC;
    } else if (lbl_803E22E0 > v) {
        lbl_803DD97C = lbl_803E22E0;
    }
    return 0;
}
#pragma scheduling reset

/* EN v1.0 0x80134834  size: 60b  Acquire two buffer slots and prime
 * the float at lbl_803DD97C with the constant from lbl_803E22E0. */
#pragma scheduling off
#pragma peephole off
void WarpstoneUI_initialise(void)
{
    lbl_803DD984 = textureLoadAsset(0x4FA);
    lbl_803DD980 = textureLoadAsset(0x5E3);
    lbl_803DD97C = lbl_803E22E0;
}
#pragma peephole reset
#pragma scheduling reset

/* EN v1.0 0x80134BC4  size: 32b  Reset the per-frame state group:
 * latch lbl_803DD993 = 1 and zero five halfword/byte counters. */
#pragma scheduling off
#pragma peephole off
void creditsStart(void)
{
    lbl_803DD993 = 1;
    lbl_803DD994 = 0;
    lbl_803DD996 = 0;
    lbl_803DD9A8 = 0;
    lbl_803DD998 = 0;
    lbl_803DD9AA = 0;
}
#pragma peephole reset
#pragma scheduling reset

/* EN v1.0 0x80134BE8  size: 60b  Predicate. Returns 1 when the value
 * from getCurUiDll is in {2..6} or equals 7, else 0. */
int gameTextFn_80134be8(void)
{
    int x = getCurUiDll();
    if ((u32)(x - 2) <= 4 || x == 7) {
        return 1;
    }
    return 0;
}

/* EN v1.0 0x80133934  size: 52b  Release-and-clear pair: when
 * minimapTexture is non-null, release via textureFree and zero both
 * minimapTexture and lbl_803DD92C. */
void fn_80133934(void)
{
    if (minimapTexture != NULL) {
        textureFree(minimapTexture);
        minimapTexture = NULL;
        lbl_803DD92C = NULL;
    }
}

/* EN v1.0 0x801375A0  size: 40b  Reset debug log/print state: rewind
 * debugLogEnd to the start of the buffer and reload the print x/y
 * coordinates from saved values. */
extern u32 lbl_803DDA00;
extern u32 lbl_803DDA08;
extern u16 debugPrintXpos;
extern u16 debugPrintYpos;
#pragma scheduling off
#pragma peephole off
void fn_801375A0(void) {
    u32 yp;
    u32 xp;
    debugLogEnd = debugLogBuffer;
    yp = lbl_803DDA08 & 0xffff;
    debugPrintYpos = (u16)yp;
    xp = lbl_803DDA00 & 0xffff;
    debugPrintXpos = (u16)xp;
}
#pragma peephole reset
#pragma scheduling reset

/* EN v1.0 0x80138908  size: 24b  Bit setter at bit 6 (0x40) of obj->_b8->_58.
 * 83% — target has a leading `clrlwi r4,r4,24` that MWCC elides since
 * the rlwimi only uses bit 0 of r4. No C form found to force it. */
void fn_80138908(int *obj, u8 v) {
    u8* x = *(u8**)((char*)obj + 0xb8);
    u8 b = *(u8*)(x + 0x58);
    *(u8*)(x + 0x58) = (u8)((b & ~0x40) | ((v & 1) << 6));
}

/* EN v1.0 0x80135BF0  size: 60b  titlescreen_free: if obj->_46 == 0x77d,
 * trigger Music_Trigger(0x3a, 0) and clear lbl_803DD993. */
extern void Music_Trigger(s32 triggerId, s32 mode);
#pragma peephole off
void titlescreen_free(u8* obj) {
    if (*(s16*)(obj + 0x46) == 0x77d) {
        Music_Trigger(0x3a, 0);
        lbl_803DD993 = 0;
    }
}
#pragma peephole reset

/* EN v1.0 0x801388D0  size: 56b  Stash 4 args to four globals and resume
 * the thread at &lbl_803AB118. */
extern u8 lbl_803AB118[];
extern s16 lbl_803DDA40;
extern u32 lbl_803DDA3C;
extern u32 lbl_803DDA38;
extern u32 lbl_803DDA34;
extern void OSResumeThread(u8* thread);
#pragma scheduling off
void fn_801388D0(s16 a, u32 b, u32 c, u32 d) {
    lbl_803DDA40 = a;
    lbl_803DDA3C = b;
    lbl_803DDA38 = c;
    lbl_803DDA34 = d;
    OSResumeThread(lbl_803AB118);
}
#pragma scheduling reset

/* EN v1.0 0x801334E0  size: 60b  Gate: when lbl_803DD944 == 2 (s8 compare)
 * and lbl_803DBBB0 != 0, latch lbl_803DD928 = 5 and return 1; else
 * return 0 without touching the latch. */
extern s8 lbl_803DD944;
extern u8 lbl_803DBBB0;
extern u8 lbl_803DD928;
#pragma peephole off
#pragma scheduling off
u8 fn_801334E0(void)
{
    u32 act = 0;
    if (lbl_803DD944 == 2 && lbl_803DBBB0 != 0) {
        act = 1;
    }
    act = (u8)act;
    if (act == 0) return (u8)act;
    lbl_803DD928 = 5;
    return (u8)act;
}
#pragma scheduling reset
#pragma peephole reset

extern void OSSetErrorHandler(int kind, void *handler);
extern void OSCreateThread(u8 *thread, void *entry, void *arg, void *stack_top, int stack_size, int prio, int flags);
extern void fn_80137DF8(void);
extern u8 lbl_803AB428[];
#pragma scheduling off
#pragma peephole off
void fn_80137D28(void)
{
  OSSetErrorHandler(0, (void *)fn_801388D0);
  OSSetErrorHandler(1, (void *)fn_801388D0);
  OSSetErrorHandler(2, (void *)fn_801388D0);
  OSSetErrorHandler(11, (void *)fn_801388D0);
  OSSetErrorHandler(13, (void *)fn_801388D0);
  OSSetErrorHandler(15, (void *)fn_801388D0);
  OSSetErrorHandler(3, (void *)fn_801388D0);
  OSSetErrorHandler(5, (void *)fn_801388D0);
  OSCreateThread(lbl_803AB118, (void *)fn_80137DF8, 0, lbl_803AB428 + 4096, 4096, 0, 1);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int trickyFindNearestUsableBaddie(int p1, int p2, f32 maxRadius)
{
  extern int dll_19_func1B(int);
  extern int *gBaddieControlInterface;
  extern int *gMapEventInterface;
  extern f32 fn_8014C5D0(int);
  extern int *ObjGroup_GetObjects(int, int *);
  extern int ObjGroup_ContainsObject(int, int);
  extern f32 vec3f_distanceSquared(int, int);
  extern f32 lbl_803E23DC;
  int *objs;
  int closest = 0;
  f32 bestDistSq;
  int count;
  int i;

  bestDistSq = maxRadius;
  objs = ObjGroup_GetObjects(3, &count);
  bestDistSq = bestDistSq * bestDistSq;

  for (i = 0; i < count; i++) {
    int *data;
    f32 obj_extra;
    int v1, v2;
    s32 g1, g2;

    if (dll_19_func1B(*objs) != 0) {
      obj_extra = (**(f32 (**)(int))((char *)(*gBaddieControlInterface) + 0x60))(*objs);
    } else {
      obj_extra = fn_8014C5D0(*objs);
    }

    data = (int *)*(int *)(*objs + 0x4c);
    g1 = *(s16 *)((char *)data + 0x18);
    if (g1 == -1) {
      v1 = 0;
    } else {
      v1 = GameBit_Get(g1);
    }
    g2 = *(s16 *)((char *)data + 0x1a);
    if (g2 == -1) {
      v2 = 1;
    } else {
      v2 = GameBit_Get(g2);
    }

    if (ObjGroup_ContainsObject(*objs, 49) == 0 &&
        obj_extra > lbl_803E23DC &&
        v1 == 0 &&
        v2 != 0) {
      if (*(s16 *)(*objs + 0x46) != 2129) {
        if ((**(int (**)(int))((char *)(*gMapEventInterface) + 0x68))(*(int *)((char *)data + 0x14)) != 0) {
          if (p2 == 0) {
            s16 m = *(s16 *)(*objs + 0x46);
            if (m == 1022 || m == 1239 || m == 636 || m == 593) goto next;
          }
          {
            f32 dist = vec3f_distanceSquared(p1 + 0x18, *objs + 0x18);
            if (dist < bestDistSq) {
              bestDistSq = dist;
              closest = *objs;
            }
          }
        }
      }
    }
  next:
    objs++;
  }
  return closest;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_80138D7C(int obj, int p2)
{
  extern int *gObjectTriggerInterface;
  extern void *Obj_GetActiveModel(int);
  extern void Obj_SetModelColorOverrideRecursive(int, int, int, int, int, int);
  extern f32 timeDelta;
  extern f32 lbl_803E23DC;
  extern f32 lbl_803E23E0;
  extern f32 lbl_803E23E8;
  extern f32 lbl_803E2408;
  extern f32 lbl_803E240C;
  u8 ratio = (u8)((s32)(s8)*(u8 *)(*(int *)(p2 + 0) + 2) / 5);

  if (*(u8 *)(p2 + 0x82c) != ratio) {
    f32 t;
    if (GameBit_Get(1005) == 0) {
      GameBit_Set(1005, 1);
      (**(void (**)(int, int, int))((char *)(*gObjectTriggerInterface) + 0x48))(5, obj, -1);
      *(u32 *)(p2 + 0x54) = *(u32 *)(p2 + 0x54) | 0x4000;
      *(f32 *)(p2 + 0x828) = *(f32 *)(p2 + 0x828) + lbl_803E2408;
    }
    *(f32 *)(p2 + 0x828) = *(f32 *)(p2 + 0x828) - timeDelta;
    t = *(f32 *)(p2 + 0x828);
    if (t <= lbl_803E2408) {
      if (t > lbl_803E23DC) {
        f32 alpha;
        if (t > lbl_803E23E0) {
          alpha = lbl_803E23E8 - (t - lbl_803E23E0) / lbl_803E23E0;
        } else {
          *(u8 *)(*(int *)((char *)Obj_GetActiveModel(obj) + 0x34) + 8) = ratio;
          alpha = *(f32 *)(p2 + 0x828) / lbl_803E23E0;
        }
        Obj_SetModelColorOverrideRecursive(obj, 255, 255, 255, (s32)(lbl_803E240C * alpha), 1);
      } else {
        *(u8 *)(p2 + 0x82c) = ratio;
        Obj_SetModelColorOverrideRecursive(obj, 0, 0, 0, 0, 0);
      }
    }
  }
  return 0;
}
#pragma peephole reset
#pragma scheduling reset

extern void ObjModel_SetBlendChannelTargets(int model, int channel, int p3, int p4, f32 weight, int p6);
extern void ObjModel_SetBlendChannelWeight(int model, int channel, f32 weight);
extern f32 lbl_803E23DC;
extern f32 lbl_803E23E0;
extern f32 lbl_803E23E4;
extern f32 lbl_803E23E8;
extern f32 lbl_803E23EC;
extern f32 lbl_803E23F0;
extern f32 lbl_803E23F4;
extern f32 lbl_803E23F8;
extern f64 lbl_803E2400;

#define TUMBLEWEED_BLEND_FLAGS_OFFSET 0x82e
#define TUMBLEWEED_BLEND_WEIGHT_OFFSET 0x830
#define TUMBLEWEED_BLEND_VELOCITY_OFFSET 0x834
#define TUMBLEWEED_BLEND_FLAG_PENDING 0x80
#define TUMBLEWEED_BLEND_FLAG_ACTIVE 0x40

/* Tricky_updateBlendChannelWeight: weighted blend-channel animator. On state[0x82e] bit 0x80,
 * primes channel 1 (weight 0, target weight ratio at +0x830) and latches
 * the active flag. While bit 0x40 is set, ramps state[0x830] toward
 * (s8)data[0] / (s8)data[1] with acceleration lbl_803E23E4 and damping
 * lbl_803E23F0, clamps to [0, lbl_803E23E8], and pushes the result to the
 * model's blend channel 1 as `lbl_803E23F8 * weight - lbl_803E23E8`. */
#pragma scheduling off
#pragma peephole off
void Tricky_updateBlendChannelWeight(int obj, u8* state) {
    extern void* Obj_GetActiveModel(int obj);
    int model;
    f32 target;
    Obj_GetActiveModel(obj);
    if ((u32)((state[TUMBLEWEED_BLEND_FLAGS_OFFSET] >> 7) & 1) != 0) {
        model = (int)Obj_GetActiveModel(obj);
        ObjModel_SetBlendChannelTargets(model, 1, -1, 0x1a, lbl_803E23DC, 0x21);
        *(f32*)(state + TUMBLEWEED_BLEND_WEIGHT_OFFSET) = lbl_803E23E0;
        ObjModel_SetBlendChannelWeight(model, 0, lbl_803E23DC);
        state[TUMBLEWEED_BLEND_FLAGS_OFFSET] =
            state[TUMBLEWEED_BLEND_FLAGS_OFFSET] & ~TUMBLEWEED_BLEND_FLAG_PENDING;
        state[TUMBLEWEED_BLEND_FLAGS_OFFSET] =
            state[TUMBLEWEED_BLEND_FLAGS_OFFSET] | TUMBLEWEED_BLEND_FLAG_ACTIVE;
    }
    if ((u32)((state[TUMBLEWEED_BLEND_FLAGS_OFFSET] >> 6) & 1) != 0) {
        u8* data = *(u8**)(state + 0);
        target = (f32)(u32)data[0] / (f32)(u32)data[1];
        if (target > *(f32*)(state + TUMBLEWEED_BLEND_WEIGHT_OFFSET)) {
            *(f32*)(state + TUMBLEWEED_BLEND_VELOCITY_OFFSET) =
                lbl_803E23E4 * timeDelta + *(f32*)(state + TUMBLEWEED_BLEND_VELOCITY_OFFSET);
            *(f32*)(state + TUMBLEWEED_BLEND_WEIGHT_OFFSET) =
                *(f32*)(state + TUMBLEWEED_BLEND_VELOCITY_OFFSET) * timeDelta +
                *(f32*)(state + TUMBLEWEED_BLEND_WEIGHT_OFFSET);
            if (*(f32*)(state + TUMBLEWEED_BLEND_WEIGHT_OFFSET) > lbl_803E23E8) {
                *(f32*)(state + TUMBLEWEED_BLEND_VELOCITY_OFFSET) = lbl_803E23DC;
                *(f32*)(state + TUMBLEWEED_BLEND_WEIGHT_OFFSET) = lbl_803E23E8;
            } else if (*(f32*)(state + TUMBLEWEED_BLEND_WEIGHT_OFFSET) > target) {
                if (*(f32*)(state + TUMBLEWEED_BLEND_VELOCITY_OFFSET) < lbl_803E23EC) {
                    *(f32*)(state + TUMBLEWEED_BLEND_VELOCITY_OFFSET) = lbl_803E23DC;
                    *(f32*)(state + TUMBLEWEED_BLEND_WEIGHT_OFFSET) = target;
                } else {
                    *(f32*)(state + TUMBLEWEED_BLEND_VELOCITY_OFFSET) =
                        *(f32*)(state + TUMBLEWEED_BLEND_VELOCITY_OFFSET) * lbl_803E23F0;
                }
            }
        } else if (target < *(f32*)(state + TUMBLEWEED_BLEND_WEIGHT_OFFSET)) {
            *(f32*)(state + TUMBLEWEED_BLEND_VELOCITY_OFFSET) =
                *(f32*)(state + TUMBLEWEED_BLEND_VELOCITY_OFFSET) - lbl_803E23E4 * timeDelta;
            *(f32*)(state + TUMBLEWEED_BLEND_WEIGHT_OFFSET) =
                *(f32*)(state + TUMBLEWEED_BLEND_VELOCITY_OFFSET) * timeDelta +
                *(f32*)(state + TUMBLEWEED_BLEND_WEIGHT_OFFSET);
            if (*(f32*)(state + TUMBLEWEED_BLEND_WEIGHT_OFFSET) < lbl_803E23DC) {
                *(f32*)(state + TUMBLEWEED_BLEND_VELOCITY_OFFSET) = lbl_803E23DC;
                *(f32*)(state + TUMBLEWEED_BLEND_WEIGHT_OFFSET) = lbl_803E23DC;
            }
            if (*(f32*)(state + TUMBLEWEED_BLEND_WEIGHT_OFFSET) < target) {
                if (*(f32*)(state + TUMBLEWEED_BLEND_VELOCITY_OFFSET) > lbl_803E23F4) {
                    *(f32*)(state + TUMBLEWEED_BLEND_VELOCITY_OFFSET) = lbl_803E23DC;
                    *(f32*)(state + TUMBLEWEED_BLEND_WEIGHT_OFFSET) = target;
                } else {
                    *(f32*)(state + TUMBLEWEED_BLEND_VELOCITY_OFFSET) =
                        *(f32*)(state + TUMBLEWEED_BLEND_VELOCITY_OFFSET) * lbl_803E23F0;
                }
            }
        }
        ObjModel_SetBlendChannelWeight(
            (int)Obj_GetActiveModel(obj), 1,
            lbl_803E23F8 * *(f32*)(state + TUMBLEWEED_BLEND_WEIGHT_OFFSET) - lbl_803E23E8);
    }
}
#pragma peephole reset
#pragma scheduling reset

extern void* gameTextGetBox(int boxId);
extern void gameTextSetColor(int r, int g, int b, int a);
extern void gameTextShow(int id);
extern f32 lbl_803DD99C;
extern u8  lbl_803DD9A0;
extern f32 lbl_803E231C;
extern f32 lbl_803E2320;
extern f32 lbl_803E2324;

#pragma scheduling off
#pragma peephole off
void titleScreenShowCopyright(u8 arg)
{
    void* tb;
    void* box;

    if (arg != 0) {
        lbl_803DD99C = lbl_803E2318;
        lbl_803DD9A0 = 0;
    } else if (lbl_803DD9A0 != 0) {
        lbl_803DD99C = lbl_803DD9B4;
    } else {
        lbl_803DD99C = lbl_803E2318;
        if (lbl_803DD9B4 > lbl_803E231C) {
            lbl_803DD9A0 = 1;
        }
    }
    tb = gameTextGet(0x3d9);
    if (*(u16*)tb != 0xffff) {
        box = gameTextGetBox(*(u8*)((char*)tb + 4));
        if (lbl_803DD9AC == 0) {
            lbl_803DD9AC = *(s16*)((char*)box + 0x16);
        }
        *(s16*)((char*)box + 0x16) =
            (s16)(lbl_803E2320 * (lbl_803E2318 - lbl_803DD99C) + (f32)lbl_803DD9AC);
        gameTextSetColor(0xff, 0xff, 0xff, (s32)(lbl_803E2324 * lbl_803DD9B0));
        gameTextShow(0x3d9);
    }
}

#pragma peephole reset
#pragma scheduling reset

extern void GXLoadPosMtxImm(f32* matrix, s32 slot);
extern void GXSetCurrentMtx(int id);
extern void GXSetProjection(f32* matrix, s32 mode);
extern void GXClearVtxDesc(void);
extern void GXSetVtxDesc(int attr, int type);
extern void GXSetCullMode(int mode);
extern void GXBegin(int type, int fmt, int n);
extern void Camera_RebuildProjectionMatrix(void);
extern f32 hudMatrix[];

typedef union {
    u8 u8;
    u16 u16;
    u32 u32;
    s16 s16;
    s32 s32;
    f32 f32;
} PPCWGPipe;
volatile PPCWGPipe GXWGFifo : (0xCC008000);

#pragma scheduling off
#pragma peephole off
void titleScreenTextDrawFunc(int x0, int y0, int x1, int y1, f32 u0, f32 v0, f32 u1, f32 v1)
{
    GXLoadPosMtxImm((f32*)lbl_803A9FE4, 0);
    GXSetCurrentMtx(0);
    GXSetProjection(hudMatrix, 1);
    GXClearVtxDesc();
    GXSetVtxDesc(9, 1);
    GXSetVtxDesc(0xd, 1);
    GXSetCullMode(0);
    GXBegin(0x80, 1, 4);
    GXWGFifo.s16 = (s16)x0; GXWGFifo.s16 = (s16)y0; GXWGFifo.s16 = -0x20;
    GXWGFifo.f32 = u0; GXWGFifo.f32 = v0;
    GXWGFifo.s16 = (s16)x1; GXWGFifo.s16 = (s16)y0; GXWGFifo.s16 = -0x20;
    GXWGFifo.f32 = u1; GXWGFifo.f32 = v0;
    GXWGFifo.s16 = (s16)x1; GXWGFifo.s16 = (s16)y1; GXWGFifo.s16 = -0x20;
    GXWGFifo.f32 = u1; GXWGFifo.f32 = v1;
    GXWGFifo.s16 = (s16)x0; GXWGFifo.s16 = (s16)y1; GXWGFifo.s16 = -0x20;
    GXWGFifo.f32 = u0; GXWGFifo.f32 = v1;
    Camera_RebuildProjectionMatrix();
}
#pragma peephole reset
#pragma scheduling reset

extern void GXSetScissor(int x, int y, int w, int h);

#pragma scheduling off
#pragma peephole off
void nameEntryTextDrawFunc(int x0, int y0, int x1, int y1, f32 u0, f32 v0, f32 u1, f32 v1)
{
    GXLoadPosMtxImm((f32*)lbl_803A9FE4, 0);
    GXSetCurrentMtx(0);
    GXSetProjection(hudMatrix, 1);
    GXClearVtxDesc();
    GXSetVtxDesc(9, 1);
    GXSetVtxDesc(0xd, 1);
    GXSetCullMode(0);
    GXSetScissor((int)((u32)*(f32*)(lbl_803A9FE4 + 0xc) + 0x39),
                 (int)((u32)*(f32*)(lbl_803A9FE4 + 0x1c) + 0x4e), 0x104, 0x16);
    GXBegin(0x80, 1, 4);
    GXWGFifo.s16 = (s16)(x0 - lbl_803DD9BC * 4 + 0x208); GXWGFifo.s16 = (s16)y0; GXWGFifo.s16 = -0x20;
    GXWGFifo.f32 = u0; GXWGFifo.f32 = v0;
    GXWGFifo.s16 = (s16)(x1 - lbl_803DD9BC * 4 + 0x208); GXWGFifo.s16 = (s16)y0; GXWGFifo.s16 = -0x20;
    GXWGFifo.f32 = u1; GXWGFifo.f32 = v0;
    GXWGFifo.s16 = (s16)(x1 - lbl_803DD9BC * 4 + 0x208); GXWGFifo.s16 = (s16)y1; GXWGFifo.s16 = -0x20;
    GXWGFifo.f32 = u1; GXWGFifo.f32 = v1;
    GXWGFifo.s16 = (s16)(x0 - lbl_803DD9BC * 4 + 0x208); GXWGFifo.s16 = (s16)y1; GXWGFifo.s16 = -0x20;
    GXWGFifo.f32 = u0; GXWGFifo.f32 = v1;
    GXSetScissor(0, 0, 0x280, 0x1e0);
    Camera_RebuildProjectionMatrix();
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_801343CC(u8* src, u8* dst, u8* ids, int count, int* out)
{
    u8* lastDst;
    int n;
    int k;
    u8* idp;
    int yoff;

    lastDst = NULL;
    n = 0;
    k = 0;
    idp = ids;
    for (k = 0; k < count; k++) {
        if ((u32)GameBit_Get(*(s16*)idp) != 0) {
            n++;
        }
        idp += 4;
    }
    k = 0;
    idp = ids;
    yoff = (count - n) * 0x2a / 2 + 0x52;
    for (n = 0; n < count; n++) {
        if ((u32)GameBit_Get(*(s16*)idp) != 0) {
            memcpy(dst, src, 0x3c);
            lastDst = dst;
            *(s16*)(dst + 6) = (s16)yoff;
            *(s8*)(dst + 0x1a) = (s8)(k - 1);
            *(s8*)(dst + 0x1b) = (s8)(k + 1);
            *out = n;
            out++;
            dst += 0x3c;
            yoff += 0x2a;
            k++;
        }
        idp += 4;
        src += 0x3c;
    }
    if (lastDst != NULL) {
        *(s8*)(lastDst + 0x1b) = -1;
    }
    return k;
}
#pragma peephole reset
#pragma scheduling reset

extern f32 lbl_803E2354;
extern f32 lbl_803E2358;
extern f32 lbl_803E235C;
extern f32 lbl_803E2360;
extern f32 lbl_803E2364;
extern f32 lbl_803E2368;
extern f32 lbl_803E236C;
extern f32 lbl_803E2370;
extern f32 lbl_803E2374;
extern f32 lbl_803E2378;
extern f32 lbl_803E237C;
extern f32 lbl_803E2380;
extern f32 lbl_803E2384;
extern f32 lbl_803E2388;
extern f32 lbl_803DBC0C;
extern u8  lbl_803A9F50[0x48];
extern int *gCameraInterface;
extern void Sfx_StopFromObject(int obj, int id);
void fn_80134870(int obj, u8 *arr);

/* EN v1.0 0x80135CC8  size: 2784b  titlescreen_update: drive the title
 * screen actor anim state machine, the per-actor footstep/voice sfx flag
 * grid at lbl_803A9F50, the random blink blend, and the one-shot envfx/sky
 * setup. */
#pragma scheduling off
#pragma peephole off
void titlescreen_update(u8 *obj)
{
    extern int  randomGetRange(int min, int max);
    extern int  ObjAnim_AdvanceCurrentMove(void *obj, f32 scale, f32 dt, void *events);
    extern void characterDoEyeAnims(int obj, void *state);
    extern void fn_8003B228(int obj, void *p);
    extern int  ObjModel_HasActiveBlendChannels(int *model);
    extern void ObjModel_SetBlendChannelTargets(int model, int channel, int p3, int p4, f32 weight, int p6);
    extern void getEnvfxAct(int a, int b, int c, int d);
    extern void skyFn_80089710(int flags, int enabled, int startComplete);
    extern void skyFn_800895e0(int id, int red, int green, int blue, int m1, int m2);
    extern void skyFn_800894a8(int flags, f32 x, f32 y, f32 z);
    extern void fn_80131F0C(void);
    extern f32  timeDelta;

    u8 *state = *(u8 **)(obj + 0xb8);
    s16 t;
    u8 c;
    int evt;
    f32 f;
    int *model;
    int tmp;
    int n;
    int s;
    u8 *row;
    int col;
    u8 *p;
    u8 buf[0x1c];

    if (lbl_803DD9AB != 0) {
        if ((s8)state[0x31] != (s8)lbl_803DD990 && (s8)lbl_803DD991 == 0 &&
            (c = state[0x30]) != 0 && c != 4 && c != 3) {
            if (*(s16 *)(obj + 0x46) == 0x77d || *(s16 *)(obj + 0x46) == 0x780) {
                state[0x30] = 3;
                ObjAnim_SetCurrentMove(obj, 1, lbl_803E2318, 0);
                *(f32 *)(state + 0x34) = lbl_8031CE10[*(s16 *)(obj + 0x46) - 0x77d].moves[3];
            } else {
                state[0x30] = 0;
                ObjAnim_SetCurrentMove(obj, 0, lbl_803E22F8, 0);
                *(f32 *)(state + 0x34) = lbl_8031CE10[*(s16 *)(obj + 0x46) - 0x77d].moves[0];
            }
        }
        if ((s8)state[0x31] == (s8)lbl_803DD990 && (s8)lbl_803DD991 != 0 &&
            (c = state[0x30]) != 1 && c != 2 && c != 5) {
            state[0x30] = 1;
            ObjAnim_SetCurrentMove(obj, 1, lbl_803E22F8, 0);
            *(f32 *)(state + 0x34) = lbl_8031CE10[*(s16 *)(obj + 0x46) - 0x77d].moves[1];
            if (*(s16 *)(obj + 0x46) == 0x77e) {
                Sfx_StopFromObject((int)obj, 0x370);
                Sfx_StopFromObject((int)obj, 0x36c);
                Sfx_PlayFromObject((int)obj, 0x36d);
            }
        }
        t = *(s16 *)(obj + 0x46);
        if (t == 0x7a7) {
            *(s16 *)obj = lbl_803E2354 * timeDelta + (f32)*(s16 *)obj;
        } else if (t != 0x78a) {
            buf[0x1b] = 0;
            if (t == 0x77d && state[0x30] == 2) {
                if (*(f32 *)(obj + 0x98) < lbl_803E2358) {
                    lbl_803DBC0C = f = lbl_803E235C * (f32)(int)randomGetRange(0x32, 0x96);
                } else {
                    f = lbl_803DBC0C;
                }
            } else {
                f = *(f32 *)(state + 0x34);
            }
            evt = ObjAnim_AdvanceCurrentMove(obj, f, timeDelta, buf);
            if (evt != 0) {
                if ((s8)state[0x31] == (s8)lbl_803DD990 && state[0x30] == 1) {
                    state[0x30] = 2;
                    ObjAnim_SetCurrentMove(obj, 2, lbl_803E22F8, 0);
                    *(f32 *)(state + 0x34) = lbl_8031CE10[*(s16 *)(obj + 0x46) - 0x77d].moves[2];
                } else if (state[0x30] == 3) {
                    state[0x30] = 0;
                    ObjAnim_SetCurrentMove(obj, 0, lbl_803E22F8, 0);
                    *(f32 *)(state + 0x34) = lbl_8031CE10[*(s16 *)(obj + 0x46) - 0x77d].moves[0];
                } else if (*(s16 *)(obj + 0x46) >= 0x77d && *(s16 *)(obj + 0x46) < 0x781) {
                    if (randomGetRange(0, 4) == 0) {
                        if ((c = state[0x30]) == 0 || c == 4) {
                            state[0x30] = 4;
                            ObjAnim_SetCurrentMove(obj, randomGetRange(3, 4), lbl_803E22F8, 0);
                            *(f32 *)(state + 0x34) =
                                lbl_8031CE10[*(s16 *)(obj + 0x46) - 0x77d].moves[1 + *(s16 *)(obj + 0xa0)];
                        } else {
                            state[0x30] = 5;
                            ObjAnim_SetCurrentMove(obj, randomGetRange(5, 6), lbl_803E22F8, 0);
                            *(f32 *)(state + 0x34) =
                                lbl_8031CE10[*(s16 *)(obj + 0x46) - 0x77d].moves[1 + *(s16 *)(obj + 0xa0)];
                        }
                    } else {
                        c = state[0x30];
                        if (c == 4) {
                            state[0x30] = 0;
                            ObjAnim_SetCurrentMove(obj, 0, lbl_803E22F8, 0);
                            *(f32 *)(state + 0x34) = lbl_8031CE10[*(s16 *)(obj + 0x46) - 0x77d].moves[0];
                        } else if (c == 5) {
                            state[0x30] = 2;
                            ObjAnim_SetCurrentMove(obj, 2, lbl_803E22F8, 0);
                            *(f32 *)(state + 0x34) = lbl_8031CE10[*(s16 *)(obj + 0x46) - 0x77d].moves[2];
                        }
                    }
                }
            }
            fn_80134870((int)obj, buf);
        }
        t = *(s16 *)(obj + 0x46);
        if (t == 0x77e && ((c = state[0x30]) == 0 || c == 4)) {
            fn_8003B228((int)obj, state);
        } else if (t >= 0x77d && t < 0x781) {
            characterDoEyeAnims((int)obj, state);
        }
        model = Obj_GetActiveModel(obj);
        if (*(u8 *)(*model + 0xf9) != 0 && ObjModel_HasActiveBlendChannels(model) == 0 &&
            randomGetRange(0xf0, 0x168) == 0xf0) {
            tmp = *(int *)((u8 *)model + 0x28);
            n = randomGetRange(0, *(u8 *)(*model + 0xf9));
            ObjModel_SetBlendChannelTargets((int)model, 0, *(s8 *)(tmp + 0xd), n - 1, lbl_803E2360, 0);
        }
        lbl_803DBC08 = -1;
        lbl_803DBC09 = -1;
        s = state[0x30];
        t = *(s16 *)(obj + 0x46);
        switch (t) {
        case 0x77d:
            break;
        case 0x77e:
            switch (s) {
            case 5:
                row = lbl_803A9F50 + (t - 0x77d) * 0x12;
                col = s * 3;
                if (row[col] != 0) {
                    if (*(f32 *)(obj + 0x98) < lbl_803E2364) row[col] = 0;
                } else if (*(f32 *)(obj + 0x98) > lbl_803E2364) {
                    Sfx_PlayFromObject((int)obj, 0x41d);
                    row[col] = 1;
                }
                break;
            }
            break;
        case 0x77f:
            switch (s) {
            case 4:
            case 5:
                if (*(s16 *)(obj + 0xa0) == 3 || *(s16 *)(obj + 0xa0) == 5) {
                    row = lbl_803A9F50 + (t - 0x77d) * 0x12;
                    col = s * 3;
                    if (row[col] != 0) {
                        if (*(f32 *)(obj + 0x98) < lbl_803E2368) row[col] = 0;
                    } else if (*(f32 *)(obj + 0x98) > lbl_803E2368) {
                        Sfx_PlayFromObject((int)obj, 0x421);
                        row[col] = 1;
                    }
                    p = lbl_803A9F50 + (*(s16 *)(obj + 0x46) - 0x77d) * 0x12 + col + 1;
                    if (*p != 0) {
                        if (*(f32 *)(obj + 0x98) < lbl_803E236C) *p = 0;
                    } else if (*(f32 *)(obj + 0x98) > lbl_803E236C) {
                        Sfx_PlayFromObject((int)obj, 0x421);
                        *p = 1;
                    }
                }
                break;
            }
            break;
        case 0x780:
            switch (s) {
            case 4:
                row = lbl_803A9F50 + (t - 0x77d) * 0x12;
                col = s * 3;
                if (row[col] != 0) {
                    if (*(f32 *)(obj + 0x98) < lbl_803E2370) row[col] = 0;
                } else if (*(f32 *)(obj + 0x98) > lbl_803E2370) {
                    Sfx_PlayFromObject((int)obj, 0x414);
                    row[col] = 1;
                }
                break;
            case 5:
                row = lbl_803A9F50 + (t - 0x77d) * 0x12;
                col = s * 3;
                if (row[col] != 0) {
                    if (*(f32 *)(obj + 0x98) < lbl_803E2374) row[col] = 0;
                } else if (*(f32 *)(obj + 0x98) > lbl_803E2374) {
                    Sfx_PlayFromObject((int)obj, 0x412);
                    row[col] = 1;
                }
                p = lbl_803A9F50 + (*(s16 *)(obj + 0x46) - 0x77d) * 0x12 + col + 1;
                if (*p != 0) {
                    if (*(f32 *)(obj + 0x98) < lbl_803E2378) *p = 0;
                } else if (*(f32 *)(obj + 0x98) > lbl_803E2378) {
                    Sfx_PlayFromObject((int)obj, 0x426);
                    *p = 1;
                }
                p = lbl_803A9F50 + (*(s16 *)(obj + 0x46) - 0x77d) * 0x12 + col + 2;
                if (*p != 0) {
                    if (*(f32 *)(obj + 0x98) < lbl_803E237C) *p = 0;
                } else if (*(f32 *)(obj + 0x98) > lbl_803E237C) {
                    Sfx_PlayFromObject((int)obj, 0x413);
                    *p = 1;
                }
                break;
            case 2:
                row = lbl_803A9F50 + (t - 0x77d) * 0x12;
                col = s * 3;
                if (row[col] != 0) {
                    if (*(f32 *)(obj + 0x98) < lbl_803E2368) row[col] = 0;
                } else if (*(f32 *)(obj + 0x98) > lbl_803E2368) {
                    Sfx_PlayFromObject((int)obj, 0x426);
                    row[col] = 1;
                }
                p = lbl_803A9F50 + (*(s16 *)(obj + 0x46) - 0x77d) * 0x12 + col + 1;
                if (*p != 0) {
                    if (*(f32 *)(obj + 0x98) < lbl_803E2380) *p = 0;
                } else if (*(f32 *)(obj + 0x98) > lbl_803E2380) {
                    Sfx_PlayFromObject((int)obj, 0x426);
                    *p = 1;
                }
                p = lbl_803A9F50 + (*(s16 *)(obj + 0x46) - 0x77d) * 0x12 + col + 2;
                if (*p != 0) {
                    if (*(f32 *)(obj + 0x98) < lbl_803E2384) *p = 0;
                } else if (*(f32 *)(obj + 0x98) > lbl_803E2384) {
                    Sfx_PlayFromObject((int)obj, 0x426);
                    *p = 1;
                }
                break;
            }
            break;
        }
        if (lbl_803DD992 == 0) {
            getEnvfxAct(0, 0, 0x21f, 0);
            skyFn_80089710(7, 1, 0);
            skyFn_800895e0(7, 0x4b, 0x64, 0x78, 0, 0);
            skyFn_800894a8(7, lbl_803E2318, lbl_803E2388, lbl_803E2388);
            (*(void (**)(u8 *, int))((char *)(*gCameraInterface) + 0x28))(obj, 0);
            lbl_803DD992 = 1;
            fn_80131F0C();
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_80134870(int obj, u8* arr)
{
    int i;
    for (i = 0; i < (s8)arr[0x1b]; i++) {
        s8 t;
        switch (*(s16*)(obj + 0x46)) {
        case 0x77d:
            t = (s8)arr[i + 0x13];
            if (t == 0) {
                Sfx_PlayFromObject(obj, 0x368);
            }
            break;
        case 0x77e:
            t = (s8)arr[i + 0x13];
            if (t == 0) {
                Sfx_PlayFromObject(obj, 0x370);
            } else if (t == 7) {
                Sfx_PlayFromObject(obj, 0x36c);
            }
            break;
        case 0x77f:
            t = (s8)arr[i + 0x13];
            if (t == 0) {
                Sfx_PlayFromObject(obj, 0x36b);
            } else if (t == 7) {
                Sfx_PlayFromObject(obj, 0x421);
            }
            break;
        case 0x780:
            t = (s8)arr[i + 0x13];
            if (t == 0) {
                Sfx_PlayFromObject(obj, 0x36a);
            } else if (t == 7) {
                Sfx_PlayFromObject(obj, 0x369);
            }
            break;
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

typedef struct { u8 s0:2; u8 s1:2; u8 s2:2; u8 s3:2; } AnimSlots;

#pragma scheduling off
#pragma peephole off
void objAnimFreeChildren(int a, int b, void** c)
{
    char buf[4];
    void *v0, *v1, *v2;

    if (*c == NULL) {
        return;
    }
    ObjLink_DetachChild(a, (int)*c);
    Obj_FreeObject(*c);
    *c = NULL;
    buf[0] = -1;
    buf[1] = -1;
    buf[2] = -1;
    v0 = *(void**)(b + 0x7a8);
    if (v0 != NULL) {
        buf[*(u8*)(b + 0x7bc) >> 6 & 3] = 1;
    }
    v1 = *(void**)(b + 0x7b0);
    if (v1 != NULL) {
        buf[*(u8*)(b + 0x7bc) >> 4 & 3] = 1;
    }
    v2 = *(void**)(b + 0x7b8);
    if (v2 != NULL) {
        buf[*(u8*)(b + 0x7bc) >> 2 & 3] = 1;
    }
    if (buf[0] == -1) {
        if (v0 != NULL) {
            ObjLink_DetachChild(a, (int)v0);
            ObjLink_AttachChild(a, *(int*)(b + 0x7a8), 0);
            ((AnimSlots*)(b + 0x7bc))->s0 = 0;
        } else if (v1 != NULL) {
            ObjLink_DetachChild(a, (int)v1);
            ObjLink_AttachChild(a, *(int*)(b + 0x7b0), 0);
            ((AnimSlots*)(b + 0x7bc))->s1 = 0;
        } else if (v2 != NULL) {
            ObjLink_DetachChild(a, (int)v2);
            ObjLink_AttachChild(a, *(int*)(b + 0x7b8), 0);
            ((AnimSlots*)(b + 0x7bc))->s2 = 0;
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

extern u16 lbl_803DBC0A;
extern u8 lbl_803DB411;
extern int loadUiDll(int dllId);
extern void TitleMenu_setSelection(int sel);
extern void streamFn_8000a380(int a, int b, int c);
extern void gameTextFn_80016810(int textId, int a, int b);
extern int* gCameraInterface;
typedef struct { u16 a; u16 b; } CreditEntry;
extern CreditEntry lbl_8031CE90[];

#pragma scheduling off
#pragma peephole off
void creditsStart_(void)
{
    u8 alpha;
    if (lbl_803DD998 >= lbl_803DBC0A) {
        if ((**(int (**)(void))(*(int*)gCameraInterface + 0x10))() == 0x57) {
            lbl_803DD993 = 0;
            loadUiDll(4);
            TitleMenu_setSelection(4);
        }
        return;
    }
    if (lbl_803DD9A8 > 0) {
        lbl_803DD9A8 = lbl_803DD9A8 - lbl_803DB411;
        if (lbl_803DD9A8 < 0) {
            lbl_803DD9A8 = 0;
        }
        return;
    }
    if (lbl_803DD996 < 0x14) {
        alpha = (u8)(lbl_803DD996 * 0xff / 0x14);
    } else if (lbl_803DD996 >= lbl_8031CE90[lbl_803DD998].b - 0x14) {
        if (lbl_803DD998 == lbl_803DBC0A - 1 && lbl_803DD9A4 == 0) {
            streamFn_8000a380(3, 2, 0xfa0);
            lbl_803DD9A4 = 1;
        }
        alpha = (u8)(0xff - (lbl_803DD996 - lbl_8031CE90[lbl_803DD998].b) * 0xff / 0x14);
    } else {
        alpha = 0xff;
    }
    gameTextSetColor(0xff, 0xff, 0xff, alpha);
    gameTextFn_80016810(lbl_8031CE90[lbl_803DD998].a, 0, 0);
    lbl_803DD994 = lbl_803DD994 + lbl_803DB411;
    lbl_803DD996 = lbl_803DD996 + lbl_803DB411;
    if (lbl_803DD996 < lbl_8031CE90[lbl_803DD998].b) {
        return;
    }
    lbl_803DD998 = lbl_803DD998 + 1;
    lbl_803DD9A8 = 0x3c;
    if (lbl_803DD998 < lbl_803DBC0A) {
        lbl_803DD996 = 0;
    }
}
#pragma peephole reset

extern void CMenu_SetFadeCounter(int v);
extern void drawTexture(void* tex, f32 x, f32 y, int alpha, int p5);
extern int lbl_803DD978;
extern int lbl_803DBBF8;
extern int lbl_803DBBFC;
extern int lbl_803DBC00;
extern int lbl_803DBC04;
typedef struct {
    s16 bit;
    u8 b2;
    u8 b3;
} WarpstoneEntry;

extern u8 lbl_8031CC50[];
extern u8 lbl_803A9DD0[];
extern WarpstoneEntry lbl_8031CC38[];
extern int lbl_803A9F38[];
extern int *gTitleMenuLinkInterface;
extern int *gMapEventInterface;

#pragma scheduling off
void WarpstoneUI_showUI(int param_1)
{
    int sel;
    int idx;
    int n;

    CMenu_SetFadeCounter(0);
    switch (lbl_803DD988) {
    case 2:
    case 3:
    case 5:
        gameTextSetColor(0xff, 0xff, 0xff, (int)lbl_803DD97C);
        gameTextFn_80016810(0x3dd, 200, lbl_803DBBF8);
        break;
    case 1:
        drawTexture(lbl_803DD980, (f32)(int)(lbl_803DBBFC - 0x1d), (f32)(int)(lbl_803DBC00 + 0xd),
                    (int)lbl_803DD97C, 0xff);
        gameTextSetColor(0xff, 0xff, 0xff, (int)lbl_803DD97C);
        gameTextShow(0x37c);
        gameTextShow(0x37d);
        gameTextShow(0x37e);
        break;
    case 4:
        gameTextSetColor(0xff, 0xff, 0xff, (int)lbl_803DD97C);
        gameTextFn_80016810(0x3dd, 200, lbl_803DBC04);
        if (lbl_803DD978 == 0) {
            n = fn_801343CC(lbl_8031CC50, lbl_803A9DD0, (u8 *)lbl_8031CC38, 6, lbl_803A9F38);
            (**(void (**)(u8*, int, int, int, int, int, int, int, int, int, int, int))
                ((char *)(*gTitleMenuLinkInterface) + 4))
                (lbl_803A9DD0, n, 0, 0, 0, 0, 0x14, 200, 0xff, 0xff, 0xff, 0xff);
            lbl_803DD978 = 1;
        }
        sel = (**(int (**)(void))((char *)(*gTitleMenuLinkInterface) + 0xc))();
        idx = (**(int (**)(void))((char *)(*gTitleMenuLinkInterface) + 0x14))();
        if (sel > 0) {
            (**(void (**)(int, u8))((char *)(*gMapEventInterface) + 0x44))
                (0x42, lbl_8031CC38[lbl_803A9F38[idx]].b2);
        }
        (**(void (**)(int))((char *)(*gTitleMenuLinkInterface) + 0x10))(param_1);
        break;
    }
    if (lbl_803DD978 != 0 && lbl_803DD988 != 4) {
        (**(void (**)(void))((char *)(*gTitleMenuLinkInterface) + 8))();
        lbl_803DD978 = 0;
    }
}
#pragma scheduling reset

typedef struct {
    u16 t0;
    u16 t1;
    u16 t2;
    u16 t3;
    u8 pad8[3];
    u8 alpha;
    f32 y;
} CreditsLine;

typedef struct {
    CreditsLine lines[9];
    u16 f90;
    u16 f92;
    u8 count;
    u8 pad95[3];
} CreditsPage;

extern CreditsPage lbl_8031C620[];
extern f32 lbl_803E22A8;
extern f32 lbl_803E22AC;
extern f32 lbl_803E22B0;
extern f32 lbl_803E22B4;
extern f32 lbl_803E22B8;

#pragma scheduling off
#pragma peephole off
int Credits_frameStart(void)
{
    u8 idx;
    int i;
    f32 cur;
    f32 t;
    f32 frac;
    CreditsPage *page;
    u8 a;

    idx = lbl_803DD970;
    if (idx < 10) {
        t = lbl_803DD968;
        lbl_803DD968 = t + timeDelta;
        if (lbl_803DD968 >= (f32)lbl_8031C620[idx].f92) {
            lbl_803DD970 = idx + 1;
        }
        if (lbl_803DD970 < 10) {
            i = 0;
            cur = lbl_803DD968;
            page = &lbl_8031C620[lbl_803DD970];
            for (; i < page->count; i++) {
                if (cur < (f32)page->lines[i].t0) {
                    a = 0;
                } else if (cur < (f32)page->lines[i].t1) {
                    frac = (cur - (f32)page->lines[i].t0) /
                           (f32)(page->lines[i].t1 - page->lines[i].t0);
                    if (frac < lbl_803E22A8) {
                        frac = lbl_803E22A8;
                    } else if (frac > lbl_803E22AC) {
                        frac = lbl_803E22AC;
                    }
                    a = lbl_803E22B0 * frac;
                } else if (cur < (f32)page->lines[i].t2) {
                    a = 0xff;
                } else if (cur < (f32)page->lines[i].t3) {
                    frac = (cur - (f32)page->lines[i].t2) /
                           (f32)(page->lines[i].t3 - page->lines[i].t2);
                    if (frac < lbl_803E22A8) {
                        frac = lbl_803E22A8;
                    } else if (frac > lbl_803E22AC) {
                        frac = lbl_803E22AC;
                    }
                    a = 0xff - (int)(lbl_803E22B0 * frac);
                } else {
                    a = 0;
                }
                page->lines[i].alpha = a;
                if (cur >= (f32)page->lines[i].t0 && cur <= (f32)page->lines[i].t3 &&
                    cur >= (f32)lbl_8031C620[lbl_803DD970].f90) {
                    page->lines[i].y = lbl_803E22B4 * (timeDelta / lbl_803E22B8) + page->lines[i].y;
                }
            }
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

extern f32 fn_80293E80(f32);
extern f32 sin(f32);
extern void hudDrawTriangle(f32 x0, f32 y0, f32 x1, f32 y1, f32 x2, f32 y2, u32 *color);
extern u32 lbl_803E2200;
extern s16 lbl_803DD930;
extern f32 lbl_803DD94C;
extern f32 lbl_803E2220;
extern f32 lbl_803E2224;
extern f32 lbl_803E2260;
extern f32 lbl_803E2264;
extern f32 lbl_803E2268;
extern f32 lbl_803E226C;
extern f32 lbl_803E2270;
extern f32 lbl_803E2274;
extern f32 lbl_803E2278;

#pragma scheduling off
#pragma peephole off
void fn_8013351C(void)
{
    u32 col;
    u32 c2;
    f32 c0;
    f32 s0;
    f32 c1;
    f32 s1;
    f32 cc2;
    f32 s2;
    int y;

    col = lbl_803E2200;
    ((u8 *)&col)[3] = (u8)lbl_803DD930;
    lbl_803DD94C = -(lbl_803E2260 * timeDelta - lbl_803DD94C);
    if (lbl_803DD94C > lbl_803E2224) {
        lbl_803DD94C = lbl_803DD94C - lbl_803E2264;
    }
    c0 = lbl_803E2268 * fn_80293E80((lbl_803E2220 * lbl_803DD94C) / lbl_803E2224);
    s0 = lbl_803E2268 * sin((lbl_803E2220 * lbl_803DD94C) / lbl_803E2224);
    c1 = lbl_803E226C * fn_80293E80((lbl_803E2220 * (lbl_803DD94C + lbl_803E2270)) / lbl_803E2224);
    s1 = lbl_803E226C * sin((lbl_803E2220 * (lbl_803DD94C + lbl_803E2270)) / lbl_803E2224);
    cc2 = lbl_803E226C * fn_80293E80((lbl_803E2220 * (lbl_803DD94C + lbl_803E2274)) / lbl_803E2224);
    s2 = lbl_803E226C * sin((lbl_803E2220 * (lbl_803DD94C + lbl_803E2274)) / lbl_803E2224);
    y = (int)lbl_803DD938 + 0x32;
    c2 = col;
    hudDrawTriangle(lbl_803E2278 - c0, (f32)y - s0,
                    lbl_803E2278 - c1, (f32)y - s1,
                    lbl_803E2278 - cc2, (f32)y - s2, &c2);
}
#pragma peephole reset
#pragma scheduling reset

extern u8 enableDebugText;
extern u16 *lbl_803DDA30;
extern void DCStoreRange(void *p, u32 nBytes);

#pragma scheduling off
#pragma peephole off
void fn_80137A00(int p1, int p2, u8 *grid, int p4)
{
    int i;
    int bit;
    int c0;
    int c1;
    int row0;
    int row1;
    int a0;
    int a1;
    int a2;
    int a3;

    if (enableDebugText != 0) {
        i = 0;
        row1 = (p2 + 1) * 0x280;
        row0 = p2 * 0x280;
        for (; i < 5; i++) {
            bit = 0;
            c0 = p1 + row0;
            a0 = c0;
            a1 = c0 + 1;
            c1 = p1 + row1;
            a2 = c1;
            a3 = c1 + 1;
            for (; bit < 8; bit++) {
                if (((1 << bit) & *grid) != 0) {
                    *(u16 *)((char *)lbl_803DDA30 + a0 * 2) = 0xC080;
                    *(u16 *)((char *)lbl_803DDA30 + a1 * 2) = 0xC080;
                    *(u16 *)((char *)lbl_803DDA30 + a2 * 2) = 0xC080;
                    *(u16 *)((char *)lbl_803DDA30 + a3 * 2) = 0xC080;
                }
                a0++;
                a1++;
                a2++;
                a3++;
            }
            DCStoreRange((char *)lbl_803DDA30 + c0 * 2, 0x10);
            DCStoreRange((char *)lbl_803DDA30 + c1 * 2, 0x10);
            row0 += 0x500;
            row1 += 0x500;
            grid++;
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

extern u16 *lbl_803DCCE8;
extern u16 *lbl_803DCCEC;
extern u8 lbl_8031D060[];

#pragma scheduling off
#pragma peephole on
void debugPrintfxy(int x, int y, char *fmt, ...)
{
    int xx;
    int yy;
    u16 *saved;
    int x0 = x;
    u8 *p1;
    u8 *p2;
    va_list args;
    char buf[272];

    if (enableDebugText != 0) {
        xx = x0;
        yy = y;
        va_start(args, fmt);
        vsprintf(buf, fmt, args);
        saved = lbl_803DDA30;
        p1 = (u8 *)buf - 1;
        p2 = (u8 *)buf - 1;
        while (p1++, *++p2 != 0) {
            switch (*p1) {
            case 0xa:
                yy += 0xc;
                xx = x0;
                break;
            case 9:
                xx += 0x40 - (xx & 0x3f);
                break;
            case 0x20:
                xx += 8;
                break;
            default:
                if (*p1 >= 0x61 && *p1 <= 0x7a) {
                    *p1 = *p1 - 0x20;
                }
                if (*p1 >= 0x21 && *p1 <= 0x5a) {
                    lbl_803DDA30 = lbl_803DCCEC;
                    fn_80137A00(xx, yy, lbl_8031D060 + (*p1 - 0x21) * 5, -1);
                    lbl_803DDA30 = lbl_803DCCE8;
                    fn_80137A00(xx, yy, lbl_8031D060 + (*p1 - 0x21) * 5, -1);
                    xx += 0xf;
                }
                break;
            }
        }
        lbl_803DDA30 = saved;
    }
}
#pragma peephole reset
#pragma scheduling reset

extern void selectTexture(char *tex, int slot);
extern void textRenderChar(int x0, int y0, int x1, int y1, f32 u0, f32 v0, f32 u1, f32 v1);
extern void gxDebugTextureFn_80078c1c(void);
extern u32 lbl_803DD9F8;
extern int lbl_803DDA0C;
extern f32 lbl_803DD9E8;
extern f32 lbl_803DD9EC;
extern u8 lbl_8031CFA0[];
extern f32 lbl_803E2390;
extern f32 lbl_803E2394;
extern f32 lbl_803E2398;
extern f32 lbl_803E239C;
extern f32 lbl_803E23A0;
extern f32 lbl_803E23A4;

#pragma scheduling off
#pragma peephole off
int fn_80136A40(int p1, int c)
{
    u8 *tbl;
    u8 first;
    int px;
    int py;
    f32 sc;

    if (c <= 0x3f) {
        if (lbl_803DD9F8 != 0) {
            if (lbl_803DDA0C != 0) {
                selectTexture((char *)lbl_803DDA24, 0);
                lbl_803DD9EC = lbl_803E2390 / (lbl_803E2394 * (f32)*(u16 *)((char *)lbl_803DDA24 + 10));
                lbl_803DD9E8 = lbl_803E2390 / (lbl_803E2394 * (f32)*(u16 *)((char *)lbl_803DDA24 + 0xc));
            }
            lbl_803DD9F8 = 0;
        }
        c -= 0x21;
    } else if (c <= 0x5f) {
        if (lbl_803DD9F8 != 1) {
            if (lbl_803DDA0C != 0) {
                selectTexture((char *)lbl_803DDA20, 0);
                lbl_803DD9EC = lbl_803E2390 / (lbl_803E2394 * (f32)*(u16 *)((char *)lbl_803DDA20 + 10));
                lbl_803DD9E8 = lbl_803E2390 / (lbl_803E2394 * (f32)*(u16 *)((char *)lbl_803DDA20 + 0xc));
            }
            lbl_803DD9F8 = 1;
        }
        c -= 0x40;
    } else if (c <= 0x7f) {
        if (lbl_803DD9F8 != 2) {
            if (lbl_803DDA0C != 0) {
                selectTexture((char *)lbl_803DDA1C, 0);
                lbl_803DD9EC = lbl_803E2390 / (lbl_803E2394 * (f32)*(u16 *)((char *)lbl_803DDA1C + 10));
                lbl_803DD9E8 = lbl_803E2390 / (lbl_803E2394 * (f32)*(u16 *)((char *)lbl_803DDA1C + 0xc));
            }
            lbl_803DD9F8 = 2;
        }
        c -= 0x60;
    }
    tbl = lbl_8031CFA0 + lbl_803DD9F8 * 0x40;
    first = tbl[c * 2];
    c = tbl[c * 2 + 1] - first + 1;
    if (lbl_803DDA0C != 0) {
        px = (int)((f32)debugPrintYpos * (lbl_803DD9D8 + (f32)lbl_803DD9E0));
        py = (int)((f32)debugPrintXpos * (lbl_803DD9DC + (f32)lbl_803DD9E1));
        gxDebugTextureFn_80078c1c();
        sc = lbl_803DD9EC;
        textRenderChar(px << 2, py << 2,
                       (int)(lbl_803E2398 * ((f32)c * (lbl_803DD9D8 + (f32)lbl_803DD9E0) + (f32)px)),
                       (int)(lbl_803E2398 * (lbl_803E239C * (lbl_803DD9DC + (f32)lbl_803DD9E1) + (f32)py)),
                       (f32)(first << 5) * sc,
                       lbl_803E23A0,
                       sc * (f32)((first + c) << 5),
                       lbl_803E23A4 * lbl_803DD9E8);
    }
    return c;
}
#pragma peephole reset
#pragma scheduling reset

extern int Camera_GetViewportYOffset(void);
extern int objIsCurModelNotZero(int obj);
extern void Sfx_StopFromObject(int obj, int id);
extern int getButtonsHeld(int p);
extern int getButtonsJustPressed(int p);
extern f32 powfCoreFast(f32 base, f32 exp);
extern int ObjGroup_FindNearestObject(int type, int obj, f32 *distOut);
extern s16 *Camera_GetCurrentViewSlot(void);
extern int getAngle(f32 dx, f32 dz);
extern int *gCameraInterface;
extern int *gGameUIInterface;
extern u8 pauseMenuState;
extern u8 lbl_803DD945;
extern u8 lbl_803DD928;
extern u8 lbl_803DD929;
extern u8 lbl_803DD92A;
extern u8 lbl_803DBBB0;
extern s8 lbl_803DBBB1;
extern u8 lbl_803DD7BA;
extern s8 lbl_803DD944;
extern int lbl_803DD934;
extern s16 lbl_803DBA6E;
extern int lbl_803DBBE8;
extern f32 lbl_803DBBB4;
extern f32 lbl_803DBBB8;
extern f32 lbl_803DBBBC;
extern f32 lbl_803DBBD4;
extern f32 lbl_803DBBD8;
extern f32 lbl_803DBBDC;
extern f32 lbl_803DBBE0;
extern f32 lbl_803DBBE4;
extern f32 lbl_803E2294;
extern f32 lbl_803E2298;
extern f32 lbl_803E229C;
extern void fn_80133818(void);

#pragma scheduling off
#pragma peephole off
void fn_8013396C(void)
{
    int player;
    int sfx;
    int held;
    int pressed;
    s16 *slot;
    int a;
    s16 d;
    s16 v2;
    f32 t;
    f32 old;
    f32 pw;
    f32 dist = lbl_803E2294;

    sfx = 0;
    player = (int)Obj_GetPlayerObject();
    if ((void *)player == NULL ||
        (**(int (**)(void))((char *)(*gCameraInterface) + 0x10))() == 0x44 ||
        (s16)Camera_GetViewportYOffset() != 0 ||
        (*(u16 *)(player + 0xb0) & 0x1000) != 0 ||
        objIsCurModelNotZero(player) == 0 ||
        pauseMenuState != 0) {
        if (lbl_803DD945 != 0) {
            Sfx_StopFromObject(0, 0x3f0);
            lbl_803DD945 = 0;
        }
    } else {
        if (lbl_803DD928 != 0) {
            lbl_803DD928 = lbl_803DD928 - 1;
        }
        if ((**(int (**)(int))((char *)(*gGameUIInterface) + 0x20))(0xc8d) != 0) {
            lbl_803DBBB0 = 1 - lbl_803DBBB0;
            switch (lbl_803DBBB0) {
            case 0:
                sfx = 0x3ec;
                break;
            case 1:
                sfx = 0x3eb;
                break;
            }
            Sfx_PlayFromObject(0, sfx);
            sfx = 0;
        }
        if (lbl_803DBBB0 == 0 && lbl_803DD7BA == 0) {
            if (lbl_803DD945 != 0) {
                Sfx_StopFromObject(0, 0x3f0);
                lbl_803DD945 = 0;
            }
        } else {
            if (lbl_803DD929 == 0) {
                lbl_803DD929 = 1;
                fn_80133818();
            }
            held = (u16)getButtonsHeld(0);
            pressed = (u16)getButtonsJustPressed(0);
            if ((held & 0xc) == 0) {
                if ((pressed & 1) != 0) {
                    lbl_803DD944 -= 1;
                    sfx = 0x3ed;
                    if (lbl_803DD944 < 0) {
                        lbl_803DD944 = 2;
                    }
                } else if ((pressed & 2) != 0) {
                    lbl_803DD944 += 1;
                    sfx = 0x3ed;
                    if (lbl_803DD944 > 2) {
                        lbl_803DD944 = 0;
                    }
                }
            }
            if (lbl_803DD7BA != 0) {
                if (lbl_803DBBB1 == -1) {
                    lbl_803DBBB1 = lbl_803DD944;
                }
                lbl_803DD944 = 2;
            } else {
                if (lbl_803DBBB1 != -1) {
                    lbl_803DD944 = lbl_803DBBB1;
                    lbl_803DBBB1 = -1;
                }
            }
            switch (lbl_803DD944) {
            case 0:
                if ((held & 4) != 0) {
                    pw = powfCoreFast(lbl_803DBBD4, timeDelta);
                    lbl_803DBBE4 = lbl_803DBBE4 * pw;
                } else if ((held & 8) != 0) {
                    pw = powfCoreFast(lbl_803DBBD8, timeDelta);
                    lbl_803DBBE4 = lbl_803DBBE4 * pw;
                } else {
                    lbl_803DBBE4 = lbl_803E2298;
                }
                t = lbl_803DBBDC;
                if (!(lbl_803DBBE4 < lbl_803DBBDC)) {
                    t = lbl_803DBBE0;
                    if (!(lbl_803DBBE4 > lbl_803DBBE0)) {
                        t = lbl_803DBBE4;
                    }
                }
                lbl_803DBBE4 = t;
                old = lbl_803DBBB4;
                lbl_803DBBB4 = old * t;
                t = lbl_803DBBB8;
                if (!(lbl_803DBBB4 < lbl_803DBBB8)) {
                    t = lbl_803DBBBC;
                    if (!(lbl_803DBBB4 > lbl_803DBBBC)) {
                        t = lbl_803DBBB4;
                    }
                }
                lbl_803DBBB4 = t;
                if (t != old) {
                    if (lbl_803DD945 == 0) {
                        Sfx_PlayFromObject(0, 0x3f0);
                        lbl_803DD945 = 1;
                    }
                } else {
                    if (lbl_803DD945 != 0) {
                        Sfx_StopFromObject(0, 0x3f0);
                        lbl_803DD945 = 0;
                    }
                }
                break;
            case 1:
                if (lbl_803DD945 != 0) {
                    Sfx_StopFromObject(0, 0x3f0);
                    lbl_803DD945 = 0;
                }
                lbl_803DD934 = ObjGroup_FindNearestObject(0x4f, player, &dist);
                if (lbl_803DD934 != 0) {
                    if (dist < lbl_803E2260) {
                        lbl_803DD92A += 1;
                        if (dist < lbl_803E229C) {
                            lbl_803DD92A += 1;
                        }
                    } else {
                        lbl_803DD92A = 0;
                    }
                    slot = Camera_GetCurrentViewSlot();
                    a = getAngle(*(f32 *)(lbl_803DD934 + 0xc) - *(f32 *)(player + 0xc),
                                 *(f32 *)(lbl_803DD934 + 0x14) - *(f32 *)(player + 0x14));
                    d = *slot + a - (u16)*(s16 *)((char *)lbl_803DBBC8[1] + 4);
                    if (d > 0x8000) {
                        d -= 0xffff;
                    }
                    if (d < -0x8000) {
                        d += 0xffff;
                    }
                    *(s16 *)((char *)lbl_803DBBC8[1] + 4) = *(s16 *)((char *)lbl_803DBBC8[1] + 4) + d / 5;
                }
                break;
            case 2:
                if (lbl_803DD945 != 0) {
                    Sfx_StopFromObject(0, 0x3f0);
                    lbl_803DD945 = 0;
                }
                v2 = lbl_803DBA6E;
                if (v2 != lbl_803DBBE8) {
                    if (v2 == -1) {
                        sfx = 0x3ef;
                    } else {
                        sfx = 0x3ee;
                    }
                }
                lbl_803DBBE8 = v2;
                break;
            }
            if ((u16)sfx != 0) {
                Sfx_PlayFromObject(0, sfx);
            }
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

extern void hudDrawRect(u32 x0, u32 y0, u32 x1, u32 y1, u32 *color);
extern void GXSetTevColor(int id, int *color);
extern void setTextColor(int p);
extern u32 lbl_803DDA08;
extern u16 lbl_803DDA14;
extern u16 lbl_803DDA16;
extern u16 lbl_803DBC10;
extern u8 lbl_803DD9F0;
extern u8 lbl_803DD9F1;
extern u8 lbl_803DD9F2;
extern u8 lbl_803DD9F3;
extern u16 lbl_803DD9F6;
extern int lbl_803DDA10;

#pragma scheduling off
#pragma peephole off
int fn_80136E00(int p1, u8 *p)
{
    u8 c;
    int w;
    u16 x2;
    u16 y;
    u16 y0;
    u16 y1;
    u16 x0;
    u32 ca;
    u32 cb;
    u32 cc;
    f32 sc;
    int rm;
    u8 c0;
    u8 c1;
    u8 c2;
    u8 c3;
    u8 colb1[4];
    u32 colw1;
    u8 colb2[4];
    u32 colw2;
    u8 colb3[4];
    u32 colw3;
    u8 *start = p;

    while ((c = *p++) != 0) {
        w = 0;
        switch (c) {
        case 0x83:
            lbl_803DDA10 = 0;
            break;
        case 0x84:
            lbl_803DDA10 = 1;
            break;
        case 0x81:
            c0 = p[0];
            c1 = p[1];
            c2 = p[2];
            c3 = p[3];
            p += 4;
            if (lbl_803DDA0C != 0) {
                colb1[0] = c0;
                colb1[1] = c1;
                colb1[2] = c2;
                colb1[3] = c3;
                colw1 = *(u32 *)colb1;
                GXSetTevColor(1, (int *)&colw1);
            }
            break;
        case 0x87:
            lbl_803DD9E0 = p[0];
            lbl_803DD9E1 = p[1];
            p += 2;
            break;
        case 0x85:
            c0 = p[0];
            c1 = p[1];
            c2 = p[2];
            c3 = p[3];
            p += 4;
            if (lbl_803DDA0C == 0) {
                lbl_803DD9F3 = c0;
                lbl_803DD9F2 = c1;
                lbl_803DD9F1 = c2;
                lbl_803DD9F0 = c3;
                setTextColor(p1);
            }
            break;
        case 0x82:
            if (lbl_803DDA0C == 0) {
                x2 = debugPrintXpos + 0xa;
                y = debugPrintYpos;
                x0 = lbl_803DDA14;
                y0 = lbl_803DDA16;
                if ((((int)(u16)(y - y0) == 0) | ((int)(u16)(x2 - x0) == 0)) == 0) {
                    if (y0 >= 2) {
                        y0 -= 2;
                    }
                    y1 = y + 2;
                    sc = lbl_803DD9D8 + (f32)lbl_803DD9E0;
                    ca = (u32)((f32)y0 * sc);
                    cb = (u32)((f32)y1 * sc);
                    sc = lbl_803DD9DC + (f32)lbl_803DD9E1;
                    cc = (u32)((f32)x0 * sc);
                    colb1[0] = lbl_803DD9F3;
                    colb1[1] = lbl_803DD9F2;
                    colb1[2] = lbl_803DD9F1;
                    colb1[3] = lbl_803DD9F0;
                    colw1 = *(u32 *)colb1;
                    hudDrawRect(ca, cc, cb, (u32)((f32)x2 * sc), &colw1);
                }
            }
            debugPrintYpos = p[0];
            debugPrintYpos |= p[1] << 8;
            debugPrintXpos = p[2];
            debugPrintXpos |= p[3] << 8;
            p += 4;
            lbl_803DDA16 = debugPrintYpos;
            lbl_803DDA14 = debugPrintXpos;
            break;
        case 0x86:
            lbl_803DBC10 = p[0];
            lbl_803DBC10 |= p[1] << 8;
            p += 2;
            break;
        case 0x20:
            w = 6;
            break;
        case 0xa:
            if (lbl_803DDA0C == 0) {
                x2 = debugPrintXpos + 0xa;
                y = debugPrintYpos;
                x0 = lbl_803DDA14;
                y0 = lbl_803DDA16;
                if ((((int)(u16)(y - y0) == 0) | ((int)(u16)(x2 - x0) == 0)) == 0) {
                    if (y0 >= 2) {
                        y0 -= 2;
                    }
                    y1 = y + 2;
                    sc = lbl_803DD9D8 + (f32)lbl_803DD9E0;
                    ca = (u32)((f32)y0 * sc);
                    cb = (u32)((f32)y1 * sc);
                    sc = lbl_803DD9DC + (f32)lbl_803DD9E1;
                    cc = (u32)((f32)x0 * sc);
                    colb2[0] = lbl_803DD9F3;
                    colb2[1] = lbl_803DD9F2;
                    colb2[2] = lbl_803DD9F1;
                    colb2[3] = lbl_803DD9F0;
                    colw2 = *(u32 *)colb2;
                    hudDrawRect(ca, cc, cb, (u32)((f32)x2 * sc), &colw2);
                }
            }
            debugPrintYpos = (u16)lbl_803DDA08;
            debugPrintXpos += 0xb;
            lbl_803DDA16 = debugPrintYpos;
            lbl_803DDA14 = debugPrintXpos;
            break;
        case 9:
            rm = debugPrintYpos % lbl_803DBC10;
            if (rm == 0) {
                w = lbl_803DBC10;
            } else {
                w = lbl_803DBC10 - rm;
            }
            break;
        default:
            w = fn_80136A40(p1, c);
            break;
        }
        if (lbl_803DDA10 != 0 && c >= 0x20 && c <= 0x7f) {
            w = 7;
        }
        debugPrintYpos += w;
        if ((f32)debugPrintYpos * (sc = lbl_803DD9D8 + (f32)lbl_803DD9E0) >
            (f32)(int)(lbl_803DD9F6 - 0x10)) {
            if (lbl_803DDA0C == 0) {
                x2 = debugPrintXpos + 0xa;
                y = debugPrintYpos;
                x0 = lbl_803DDA14;
                y0 = lbl_803DDA16;
                if ((((int)(u16)(y - y0) == 0) | ((int)(u16)(x2 - x0) == 0)) == 0) {
                    if (y0 >= 2) {
                        y0 -= 2;
                    }
                    y1 = y + 2;
                    ca = (u32)((f32)y0 * sc);
                    cb = (u32)((f32)y1 * sc);
                    sc = lbl_803DD9DC + (f32)lbl_803DD9E1;
                    cc = (u32)((f32)x0 * sc);
                    colb3[0] = lbl_803DD9F3;
                    colb3[1] = lbl_803DD9F2;
                    colb3[2] = lbl_803DD9F1;
                    colb3[3] = lbl_803DD9F0;
                    colw3 = *(u32 *)colb3;
                    hudDrawRect(ca, cc, cb, (u32)((f32)x2 * sc), &colw3);
                }
            }
            debugPrintYpos = (u16)lbl_803DDA08;
            debugPrintXpos += 0xb;
            lbl_803DDA16 = debugPrintYpos;
            lbl_803DDA14 = debugPrintXpos;
        }
    }
    return p - start;
}
#pragma peephole reset
#pragma scheduling reset

extern void drawScaledTexture(char *tex, f32 x, f32 y, int alpha, int s, int w, int h, int mode);
extern s16 fn_80130124(void);
extern u32 __cvt_fp2unsigned(f32 x);
extern u8 lbl_803DD9C0;
extern f32 lbl_803E22F0;
extern f32 lbl_803E22F4;
extern f32 lbl_803E22F8;
extern f32 lbl_803E22FC;
extern f32 lbl_803E2300;
extern f32 lbl_803E2304;
extern f64 lbl_803E2308;
extern f64 lbl_803E2310;
extern f32 lbl_803E2328;
extern f32 lbl_803E232C;
extern f32 lbl_803E2330;
extern f32 lbl_803E2334;
extern f32 lbl_803E2338;
extern f32 lbl_803E233C;
extern f32 lbl_803E2340;

#pragma scheduling off
#pragma peephole off
void gameTextBoxFn_80134d40(int p1, int p2, u32 p3)
{
    int xb;
    int yb;
    int i;
    int r;
    u8 a;
    s16 v;
    char *t;
    int box;
    f32 m;
    f32 sc3;

    lbl_803DD9C4 = lbl_803DD9C4 + timeDelta;
    if (lbl_803DD9C4 > lbl_803E22F0) {
        lbl_803DD9C4 = lbl_803DD9C4 - lbl_803E22F0;
    }
    lbl_803DD9C0 = (int)(lbl_803E232C *
                             sin(lbl_803E2330 * (lbl_803E2334 * lbl_803DD9C4) / lbl_803E22F0) +
                         lbl_803E2328);
    if (lbl_803DD9C8 > lbl_803E22F8) {
        xb = *(s16 *)((char *)lbl_803A9F98 + 0x58);
        yb = *(s16 *)((char *)lbl_803A9F98 + 0x68);
        t = (char *)lbl_803A9F98[4];
        drawScaledTexture(t,
                          (f32)(int)(xb - 0x32 + *(u16 *)((char *)lbl_803A9F98[6] + 10) + 0x5a),
                          (f32)(int)(yb - 0x10), p1, 0x100, *(u16 *)(t + 10),
                          (u32)(lbl_803E2300 * lbl_803DD9C8) + 0x10, 0);
        t = (char *)lbl_803A9F98[6];
        drawScaledTexture(t, (f32)(int)(xb + 0x28), (f32)(int)(yb - 0x10), 0xff, 0x100,
                          *(u16 *)(t + 10), (u32)(lbl_803E2300 * lbl_803DD9C8) + 0x10, 0);
        t = (char *)lbl_803A9F98[6];
        drawScaledTexture(t,
                          (f32)(int)(xb - 0x32 + *(u16 *)((char *)lbl_803A9F98[4] + 10) +
                                     *(u16 *)(t + 10) + 0x57),
                          (f32)(int)(yb - 0x10), 0xff, 0x100, *(u16 *)(t + 10),
                          (u32)(lbl_803E2300 * lbl_803DD9C8) + 0x10, 1);
        t = (char *)lbl_803A9F98[0];
        drawScaledTexture(t, (f32)(int)(xb - 0xf), (f32)(int)(yb - 0x10), 0xff, 0x100,
                          *(u16 *)(t + 10), (u32)(lbl_803E2300 * lbl_803DD9C8) + 0x10, 0);
    }
    xb = *(s16 *)((char *)lbl_803A9F98 + 0x58);
    yb = *(s16 *)((char *)lbl_803A9F98 + 0x68);
    a = lbl_803DD9C0;
    if (lbl_803DD9C8 > lbl_803E22F8) {
        a = 0xff;
    }
    drawTexture(lbl_803A9F98[1], (f32)(int)(xb - 0x18),
                (f32)(int)(yb - *(u16 *)((char *)lbl_803A9F98[1] + 0xc) + 3), 0xff, 0xff);
    drawTexture(lbl_803A9F98[7], (f32)(int)(xb + 0xa1), (f32)(int)(yb - 0x2e), a, 0xff);
    xb = *(s16 *)((char *)lbl_803A9F98 + 0x58);
    yb = *(s16 *)((char *)lbl_803A9F98 + 0x68);
    a = lbl_803DD9C0;
    if (lbl_803DD9C8 > lbl_803E22F8) {
        a = 0xff;
    }
    drawTexture(lbl_803A9F98[2], (f32)(int)(xb - 0x18),
                lbl_803E22FC + lbl_803E2300 * lbl_803DD9C8 + (f32)(int)yb, 0xff, 0xff);
    drawTexture(lbl_803A9F98[7], (f32)(int)(xb + 0xa1),
                lbl_803E2304 + lbl_803E2300 * lbl_803DD9C8 + (f32)(int)yb, a, 0xff);
    gameTextSetColor(0xff, 0xff, 0xff,
                     (int)(((f64)lbl_803DD9C0 - lbl_803E2310) * (lbl_803E2308 - (f64)lbl_803DD9C8)));
    gameTextShow(0x3da);
    drawTexture(lbl_803A9F98[3], (f32)(int)(*(s16 *)((char *)lbl_803A9F98 + 0x58) - 0x32),
                (f32)(int)(0xfe - (*(u16 *)((char *)lbl_803A9F98[3] + 10) >> 1)), 0xff, 0xff);
    if (lbl_803DD9C8 >= lbl_803E2338 && (p2 & 0xff) == 0) {
        xb = *(s16 *)((char *)lbl_803A9F98 + 0x58);
        yb = *(s16 *)((char *)lbl_803A9F98 + 0x68);
        i = 0;
        sc3 = lbl_803E2300;
        do {
            t = (char *)lbl_803A9F98[4];
            r = (u32)(sc3 * lbl_803DD9C8);
            drawScaledTexture(t,
                              (f32)(int)(xb + *(u16 *)((char *)lbl_803A9F98[6] + 10) + 0x28 +
                                         (i + 1) * -4),
                              (f32)(int)(yb - 0x10 + (i + 1) * -3),
                              (int)(u32)lbl_803DD9C0 >> ((i + 3) & 0x3f) & 0xff, 0x100,
                              *(u16 *)(t + 10) + (i + 1) * 8, r + (i + 1) * 6 + 0x10, 4);
            i++;
        } while (i < 4);
    }
    if (lbl_803DD9C8 > lbl_803E22F8 && (v = fn_80130124()) != -1) {
        box = (int)gameTextGetBox(v);
        if ((p2 & 0xff) == 0) {
            drawTexture(lbl_803A9F98[5],
                        (f32)(int)(*(s16 *)((char *)lbl_803A9F98 + 0x58) + 0x2f),
                        (f32)(int)(*(s16 *)(box + 0x16) + *(s16 *)((char *)lbl_803A9F98 + 0x68) - 1), p2, 0xff);
        }
    }
    drawScaledTexture((char *)lbl_803A9F98[18],
                      (f32)(int)((int)(lbl_803E22F0 * lbl_803DD9B0) - 0x50),
                      (f32)(int)((int)(lbl_803E22F4 * lbl_803DD9B4) + 0x1e0), 0xff, 0x100,
                      *(u16 *)((char *)lbl_803A9F98[18] + 10),
                      *(u16 *)((char *)lbl_803A9F98[18] + 0xc), 1);
    t = (char *)lbl_803A9F98[8 + ((int)((u32)lbl_803DD9C0 << 3) >> 8)];
    drawScaledTexture(t,
                      (f32)(int)((int)(lbl_803E22F0 * lbl_803DD9B0) +
                                 *(u16 *)((char *)lbl_803A9F98[18] + 10) - 0x4a),
                      (f32)(int)((int)(lbl_803E22F4 * lbl_803DD9B4) + 0x1e0), 0xff, 0x100,
                      *(u16 *)(t + 10), *(u16 *)(t + 0xc), 0);
    drawScaledTexture((char *)lbl_803A9F98[18],
                      (f32)(int)(0x280 - ((int)(lbl_803E22F0 * lbl_803DD9B0) - 0x50) -
                                 *(u16 *)((char *)lbl_803A9F98[18] + 10)),
                      (f32)(int)((int)(lbl_803E22F4 * lbl_803DD9B4) + 0x1e0), 0xff, 0x100,
                      *(u16 *)((char *)lbl_803A9F98[18] + 10),
                      *(u16 *)((char *)lbl_803A9F98[18] + 0xc), 0);
    t = (char *)lbl_803A9F98[8 + ((int)((u32)lbl_803DD9C0 << 3) >> 8)];
    drawScaledTexture(t,
                      (f32)(int)(0x27a - ((int)(lbl_803E22F0 * lbl_803DD9B0) - 0x50) -
                                 *(u16 *)((char *)lbl_803A9F98[18] + 10) - *(u16 *)(t + 10)),
                      (f32)(int)((int)(lbl_803E22F4 * lbl_803DD9B4) + 0x1e0), 0xff, 0x100,
                      *(u16 *)(t + 10), *(u16 *)(t + 0xc), 1);
    m = lbl_803DD9B4;
    if (lbl_803DD9B4 > lbl_803DD9B0) {
        m = lbl_803DD9B0;
    }
    drawTexture(lbl_803DD9D4,
                (f32)(int)((0x280 - ((int)((u32)*(u16 *)((char *)lbl_803DD9D4 + 10) * 0xbe) >> 8)) / 2),
                (f32)(int)(int)(lbl_803E2340 * m + lbl_803E233C), 0xff, 0xbe);
    if ((p3 & 0xff) != 0) {
        xb = *(s16 *)((char *)lbl_803A9F98 + 0x58);
        yb = *(s16 *)((char *)lbl_803A9F98 + 0x68);
        drawTexture(lbl_803A9F98[17], (f32)(int)(xb + 0x2f), (f32)(int)(yb + 0x14),
                    0xff, 0xff);
        drawTexture(lbl_803A9F98[16], (f32)(int)(xb + 0x2f), (f32)(int)(yb + 0x4b),
                    0xff, 0xff);
    }
}
#pragma peephole reset
#pragma scheduling reset
