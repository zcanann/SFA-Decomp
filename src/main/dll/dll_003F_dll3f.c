#include "main/texture.h"
#include "main/camera_interface.h"
#include "main/effect_interfaces.h"
#include "main/game_ui_interface.h"
#include "main/dll/tricky_state.h"
#include "main/game_object.h"
#include "main/dll/baddie/Tumbleweed.h"
#include "main/dll/FRONT/dll_39.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"
#include "stdarg.h"

typedef struct TrickyImpressState
{
    u8 pad0[0x54 - 0x0];
    u32 unk54;
    u8 pad58[0x408 - 0x58];
    f32 unk408;
    f32 unk40C;
    f32 unk410;
    u8 pad414[0x7A8 - 0x414];
    s32 unk7A8;
    u8 pad7AC[0x7B0 - 0x7AC];
    s32 unk7B0;
    u8 pad7B4[0x7B8 - 0x7B4];
    s32 unk7B8;
    u8 unk7BC;
    u8 pad7BD[0x808 - 0x7BD];
    f32 unk808;
    u8 pad80C[0x810 - 0x80C];
} TrickyImpressState;


typedef struct TitlescreenState
{
    s16 unk0;
    s16 unk2;
    s16 unk4;
    u8 pad6[0x18 - 0x6];
    f32 unk18;
    f32 unk1C;
    f32 unk20;
    u8 pad24[0x30 - 0x24];
    u8 unk30;
    s8 unk31;
    u8 pad32[0x34 - 0x32];
    f32 unk34;
} TitlescreenState;


extern uint ObjGroup_ContainsObject();
extern int ObjGroup_FindNearestObject();
extern void* ObjGroup_GetObjects();
extern undefined8 ObjLink_DetachChild();
extern undefined4 ObjLink_AttachChild();
extern undefined8 FUN_80053754();
extern undefined4 FUN_80246dcc();

extern undefined4 DAT_803dc818;
extern ObjectTriggerInterface** gObjectTriggerInterface;
extern EffectInterface** gPartfxInterface;
extern undefined4 DAT_803de5a8;
extern undefined4 DAT_803de5c4;
extern undefined4 DAT_803de62b;
extern undefined4 DAT_803de6b4;
extern undefined4 DAT_803de6b8;
extern undefined4 DAT_803de6bc;
extern undefined4 DAT_803de6c0;
extern f32 FLOAT_803e3098;

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
typedef struct MinimapRow
{
    s16 x0, x1, z0, z1, y0, y1;
    u16 gameBit;
    u8 texU, texV;
    u16 mapId;
    u8 swap;
    u8 pad13;
} MinimapRow;

typedef struct MinimapMapEntry
{
    MinimapRow* rows;
    u16 gameBit;
    u8 cellId;
    u8 count;
} MinimapMapEntry;

extern MinimapMapEntry gMinimapCellTable[];

extern int coordsToMapCell(f32 x, f32 z);
extern void* Obj_GetPlayerObject(void);
extern u32 GameBit_Get(int eventId);
extern int Camera_GetViewportYOffset(void);
extern int objIsCurModelNotZero(int obj);
extern void* gameTextGetBox(int boxId);
extern void gameTextSetColor(int r, int g, int b, int a);
extern void gameTextShow(int id);
extern void GXSetScissor(int x, int y, int w, int h);
extern void drawTexture(void* tex, f32 x, f32 y, int alpha, int p5);
extern f32 mathSinf(f32);
extern f32 mathCosf(f32);
extern void hudDrawTriangle(f32 x0, f32 y0, f32 x1, f32 y1, f32 x2, f32 y2, u32* color);
extern void hudDrawRect(u32 x0, u32 y0, u32 x1, u32 y1, u32* color);
extern void drawPartialTexture(void* tex, f32 x, f32 y, int alpha, int scale, u32 w, u32 h, u32 u, u32 v);
extern void drawHudBox(int id, int x, int y, int w, int alpha, int p6);
extern void gameTextSetCursor(int a, int b, int c);
extern void gameTextResetCursor(int n);
extern int gameTextGetCharset(void);
extern void gameTextSetCharset(int a, int b);
void fn_80133718(void);
void fn_8013351C(void);

extern u8 lbl_803DBBB0;
extern u8 lbl_803DD7BA;
extern s16 lbl_803DD7A2;
extern s16 lbl_803DBA6E;
extern u8 lbl_803DD928;
extern int lbl_803DD934;
extern u8 pauseMenuState;
extern u8 lbl_803DD75B;
extern s16 lbl_803DD930;
extern s16 lbl_803DD932;
extern u32 lbl_803DD938;
extern void* lbl_803DD92C;
extern void* minimapTexture;
extern void* lbl_803DD940;
extern u8 lbl_803DD946;
extern u8 lbl_803DD947;
extern s16 lbl_803DD948;
extern s16 lbl_803DD94A;
extern s16 lbl_803DBBD0;
extern s16 lbl_803DBBD2;
extern s8 lbl_803DD95C;
extern s8 lbl_803DD944;
extern int lbl_803DBBC0;
extern int lbl_803DBBC4;
extern f32 lbl_803DBBB4;
extern f32 lbl_803DBBB8;
extern f32 lbl_803DBBBC;
extern f32 lbl_803DBBEC;
extern f32 lbl_803DD950;
extern f32 lbl_803DD954;
extern f32 lbl_803DD958;
extern u8 framesThisStep;
extern u32 lbl_803E2204;
extern f32 lbl_803E2208;
extern f32 lbl_803E2210;
extern f32 lbl_803E2214;
extern f32 lbl_803E2218;
extern f32 lbl_803E221C;
extern f32 lbl_803E2220;
extern f32 lbl_803E2224;
extern f32 lbl_803E2228;
extern f32 lbl_803E222C;
extern f32 lbl_803E2230;
extern f32 lbl_803E2234;
extern f32 lbl_803E2238;
extern f32 lbl_803E223C;
extern f32 lbl_803E2240;
extern f32 lbl_803E2244;
extern f32 lbl_803E2248;
extern f32 lbl_803E224C;

#pragma scheduling off
#pragma peephole off
int Minimap_update(void);
#pragma peephole reset
#pragma scheduling reset


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
    if ((DAT_803de5c4 == '\x02') && (DAT_803dc818 != '\0'))
    {
        bVar1 = true;
    }
    if (!bVar1)
    {
        return;
    }
    DAT_803de5a8 = 5;
    return;
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
void FUN_80135810(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  char* param_9, undefined4 param_10, undefined4 param_11, undefined4 param_12,
                  undefined4 param_13, undefined4 param_14, undefined4 param_15, undefined4 param_16)
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
void FUN_80135c48(undefined2 param_1, undefined4 param_2, undefined4 param_3, undefined4 param_4)
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
void FUN_80135c84(int param_1, uint param_2)
{
    *(byte*)(*(int*)&((GameObject*)param_1)->extra + 0x58) =
        (byte)((param_2 & 0xff) << 6) & 0x40 | *(byte*)(*(int*)&((GameObject*)param_1)->extra + 0x58) & 0xbf;
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

    iVar1 = *(int*)&((GameObject*)param_1)->extra;
    *(uint*)(iVar1 + 0x54) = *(uint*)(iVar1 + 0x54) | 0x80000000;
    *(float*)(iVar1 + 0x808) = FLOAT_803e3098;
    return;
}


/* ===== EN v1.0 retargeted leaves ========================================= */

extern u8 warpstoneUIState;
extern u32 lbl_803DD9B8;
extern u32 lbl_803DD9BC;
extern u8 lbl_803DD9AB;
extern u8 showCredits;

/* 4-byte and 8-byte trivial leaves. */
void dll_3F_frameEnd_nop(void)
{
}

void Credits_render(void);

void Credits_frameEnd(void);

void WarpstoneUI_frameEnd(void);

void reportAllocFail(void);

int dll_3F_frameStart_ret_0(void) { return 0; }
u8 shouldShowCredits(void);

/* EN v1.0 0x801334D4  size: 12b  u16-narrow getter for lbl_803DD938. */
u16 getMinimapY(void);

/* EN v1.0 0x801344F0  size: 12b  u8 setter writing arg low byte to
 * warpstoneUIState. */
#pragma peephole off
void WarpstoneUI_setState(int val);
#pragma peephole reset

/* EN v1.0 0x80135814  size: 12b  Two-word setter for state pair. */
void fn_80135814(u32 a, u32 b);

/* EN v1.0 0x801368D4  size: 12b  Clear lbl_803DD9AB to 0. */
void titleScreenFn_801368d4(void);

/* EN v1.0 0x80138F78  size: 12b  obj->_b8->_14 (f32). */
f32 fn_80138F78(u8* obj);
/* EN v1.0 0x80138F84  size: 12b  obj->_b8->_24 (u32). */
u32 fn_80138F84(u8* obj);
/* EN v1.0 0x80138F90  size: 12b  obj->_b8->_414 (s16). */
s16 fn_80138F90(u8* obj);
/* EN v1.0 0x80138F9C  size: 12b  Returns Tricky's queued path particle position. */
void* trickyGetQueuedPathParticlePos(u8* obj);

/* EN v1.0 0x80135BC4  size: 8b   titlescreen_getExtraSize -> 56. */
int titlescreen_getExtraSize(void);

/* EN v1.0 0x80135CC4  size: 4b   titlescreen_hitDetect (empty stub). */
void titlescreen_hitDetect(void);

/* EN v1.0 0x80135BCC  size: 36b  titlescreen_getObjectTypeId: returns 74 if
 * obj->_46 (s16) is in [1917, 1920], else returns 0. */
int titlescreen_getObjectTypeId(u8* obj);

extern void titlescreen_free(u8 * obj);
extern void titlescreen_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
extern void titlescreen_update(u8 * obj);
extern void titlescreen_init(u8 * obj, u8 * p);
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
extern u8 lbl_803DD992;
extern f32 lbl_803DD968;
extern f32 lbl_803E22A8;
extern u8 lbl_803DD970;
extern void* lbl_803DD974;
extern void* lbl_803DD96C;
extern void* gameTextGet(s32);

/* EN v1.0 0x801368E0  size: 124b  titlescreen_release: free the main
 * buffer at lbl_803DD9D4 and walk the 19-slot table at lbl_803A9F98
 * releasing each non-null entry, then clear the busy byte at
 * lbl_803DD992. */
#pragma scheduling off
#pragma peephole off
void titlescreen_release(void);
#pragma peephole reset
#pragma scheduling reset

extern s8 lbl_803DBC08;
extern s8 lbl_803DBC09;
extern u8 lbl_803DD990;
extern u8 lbl_803DD991;
extern u8 lbl_803DC968;
extern f32 lbl_803DD9D0;
extern f32 lbl_803DD9CC;
extern f32 lbl_803DD9C4;
extern f32 lbl_803DD9B4;
extern f32 lbl_803DD9B0;
extern int lbl_803DD9AC;
extern f32 lbl_803E2318;
extern f32 lbl_803E22F8;
extern u8 lbl_803A9FE4[0x34];
extern s16 lbl_8031CDE8[];
extern void PSMTXIdentity(void*);

/* EN v1.0 0x8013695C  size: 228b  titlescreen_initialise: reset state
 * bytes, load the main texture (asset 0x647 or 0xC5 depending on
 * lbl_803DC968), identity the matrix, then load the 19-entry texture
 * table from the id list at lbl_8031CDE8 into lbl_803A9F98. */
#pragma scheduling off
#pragma peephole off
void titlescreen_initialise(void);
#pragma peephole reset
#pragma scheduling reset

extern u8 lbl_803DD9AA;
extern int lbl_803DD9A4;
extern void objRenderFn_8003b8f4(f32);

/* EN v1.0 0x80135C2C  size: 152b  titlescreen_render: when visible and
 * ready, render via objRenderFn; once the credits flag fires, set the
 * one-shot trigger 0x57 and release the attract-mode movie buffers. */
#pragma scheduling off
#pragma peephole off
void titlescreen_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
#pragma peephole reset
#pragma scheduling reset

typedef struct TitleAnimMoves
{
    f32 moves[8];
} TitleAnimMoves;

extern TitleAnimMoves lbl_8031CE10[];
extern void ObjModel_SetRenderCallback(int* model, void* cb);
extern void AttractMovie_DrawTextureCallback(void);

/* EN v1.0 0x801367A8  size: 252b  titlescreen_init: seed the object's
 * state from its descriptor id (obj->_46), pick the anim move and blend
 * float per id range, and for the attract id install the movie draw
 * callback. */
#pragma scheduling off
#pragma peephole off
void titlescreen_init(u8* obj, u8* p);
#pragma peephole reset
#pragma scheduling reset

extern f32 lbl_803E23E8;

/* EN v1.0 0x80139164  size: 252b  Tricky_emitQueuedPathParticles: when b->_54 carries the
 * spawn flag, build a particle descriptor on the stack from a's heading
 * and the delta to b's position, then emit it 20 times via the partfx
 * interface and clear the flag. */
#pragma scheduling off
#pragma peephole off
void Tricky_emitQueuedPathParticles(u8* a, u8* b);
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int trickySelectQueuedCommandTarget(u8* state, int commandType);
#pragma peephole reset
#pragma scheduling reset

/* EN v1.0 0x80134388  size: 68b  Acquire two buffers and prime the
 * float at lbl_803DD968. */
#pragma scheduling off
void Credits_initialise(void);
#pragma scheduling reset

/* EN v1.0 0x80138F14  size: 100b  GameBit-gated bit toggle on
 * obj->_b8->_54: requires GameBit_Get(0x4E4); sets bit 0x10000 then
 * checks bit 0x10. Returns 1 only when the post-OR check passes. */
#pragma peephole off
#pragma scheduling off
int trickyFn_80138f14(u8* obj);
#pragma scheduling reset
#pragma peephole reset

extern f32 lbl_803E2344;
extern f32 lbl_803E2348;
extern f32 lbl_803E234C;
extern f32 lbl_803E2350;
extern f32 lbl_803DD9C8;
extern void PSMTXTrans(void*, f32, f32, f32);

extern void* lbl_803DBBC8[2];
extern void Obj_FreeObject(void*);

extern f32 lbl_803E23B8;
extern f32 lbl_803DD9D8;
extern f32 lbl_803DD9DC;
extern u8 lbl_803DD9E0;
extern u8 lbl_803DD9E1;
extern void* lbl_803DDA1C;
extern void* lbl_803DDA20;
extern void* lbl_803DDA24;
extern void* debugLogEnd;
extern u8 debugLogBuffer[0x1100];
extern u32 getScreenResolution(void);
extern int vsprintf(char* s, const char* format, va_list arg);

/* EN v1.0 0x80137998  size: 104b  Title-screen system init. Calls
 * getScreenResolution, primes the two float counters, clears two state bytes,
 * acquires three sized buffers (605/1/2 bytes) and primes the
 * debugLogEnd cursor to the start of the 0x1100-byte arena. */
#pragma scheduling off
void fn_80137998(void);
#pragma scheduling reset

/* EN v1.0 0x80137520  size: 128b  Emit a SetColor record (tag 0x81 +
 * 4 RGBA bytes + 0 terminator) into the debug log; aborts when the
 * record counter at lbl_803DD9E4 has already exceeded 0xFA. */
extern int lbl_803DD9E4;
#pragma scheduling off
void debugPrintSetColor(u8 r, u8 g, u8 b, u8 a);
#pragma scheduling reset

extern int Sfx_IsPlayingFromObjectChannel(u8*, int);
extern void objAudioFn_800393f8(u8*, u8*, int, int, int, int);

/* EN v1.0 0x80138920  size: 192b  Drop-anim trigger guard. Returns 1
 * (and dispatches the drop anim via objAudioFn_800393f8) only when:
 *   - bit 0x40 of obj->_b8->_58 is clear,
 *   - the target halfword obj->_a0 is OUTSIDE the [41, 47] window,
 *   - Sfx_IsPlayingFromObjectChannel(obj, 16) returns 0. */
#pragma scheduling off
#pragma peephole off
int fn_80138920(u8* obj, int arg1, int arg2);
#pragma peephole reset
#pragma scheduling reset

extern int Obj_AllocObjectSetup(int a, int b);
extern int Obj_SetupObject(int obj, int b, int c, int d, int e);
extern f32 lbl_803E2284;
extern f32 lbl_803E2288;
extern f32 lbl_803E228C;
extern f32 lbl_803E2290;

#pragma dont_inline on
#pragma scheduling off
#pragma peephole off
void fn_80133818(void);
#pragma peephole reset
#pragma scheduling reset
#pragma dont_inline reset

extern u8 gameTimerIsRunning(void);
extern void gameTimerRun(void* obj);
extern int sprintf(char* buf, const char* fmt, ...);
extern f32 lbl_803E22A0;
__declspec(section ".sdata") extern char lbl_803DBBF0[];

#pragma scheduling off
#pragma peephole off
void fn_80133F70(void* obj)
{
    char buf[12];
    f32 threshold;
    int a;
    int b;
    int c;
    void* player;
    void* nearest;

    threshold = lbl_803E22A0;
    a = 0;
    b = 0;
    c = 0;
    if (gameTimerIsRunning())
    {
        gameTimerRun(obj);
    }
    player = (void*)Obj_GetPlayerObject();
    nearest = (void*)ObjGroup_FindNearestObject(9, player, &threshold);
    if (nearest != NULL)
    {
        ((void (*)(void*, int*, int*, int*))(*(void***)((GameObject*)nearest)->anim.dll)[21])(nearest, &a, &b, &c);
    }
    b = c - (b - a);
    if (b < 0)
    {
        b = 0;
    }
    sprintf(buf, lbl_803DBBF0, b);
}
#pragma peephole reset
#pragma scheduling reset

extern void viewFn_80129cbc(f32 a, f32 b, f32 c);
extern void viewFn_80129c74(void);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void objRender(int a, int b, int c, int d, void* obj, int f);
extern int* Obj_GetActiveModel(void* obj);
extern u8 lbl_803DD92A;
extern f32 lbl_803E2278;
extern f32 lbl_803E227C;
extern f32 lbl_803E2280;

#pragma scheduling off
#pragma peephole off
void fn_80133718(void);
#pragma peephole reset
#pragma scheduling reset

/* Variadic debug logger: append formatted text while the debug arena has room. */
#pragma scheduling off
void debugPrintf(char* fmt, ...);
#pragma scheduling reset

/* Variadic debug-print sink: retail keeps only the ABI varargs spill frame. */
void fn_80137948(char* fmt, ...);

/* EN v1.0 0x80133EA4  size: 156b  Two-step shutdown helper. Releases
 * the buffers at minimapTexture and lbl_803DD940 (the first only if
 * non-null), then walks the 2-slot live-objects table at lbl_803DBBC8
 * tearing down each non-null entry via Obj_FreeObject. Both buffer
 * pointers are zeroed at the end. */
void Minimap_release(void);

/* EN v1.0 0x80135820  size: 136b  Set up the title-screen translation
 * matrix at lbl_803A9FE4 and derive the three normalized cursor
 * positions from the supplied (a, b) coordinates. */
#pragma scheduling off
void titleScreenPositionElements(f32 a, f32 b);
#pragma scheduling reset

extern void* lbl_803DD960;
/* lbl_803DD940 declared later as void* */
extern f32 lbl_803E2408;

/* EN v1.0 0x80133F40  size: 48b  Acquire a 0xBE5-byte buffer via
 * textureLoadAsset into lbl_803DD940; reset frame counter at lbl_803DD938. */
#pragma scheduling off
void Minimap_initialise(void);
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
void dll_3F_initialise(void)
{
    lbl_803DD960 = textureLoadAsset(0x47A);
}
#pragma scheduling reset

/* EN v1.0 0x80134364  size: 36b  Release lbl_803DD974 buffer. */
void Credits_release(void);

/* EN v1.0 0x801368A4  size: 32b  Two-byte state push: if arg differs
 * from lbl_803DD991, save old to lbl_803DBC09 and set new. */
void titleScreenFn_801368a4(s8 arg);

/* EN v1.0 0x801368C4  size: 16b  Two-byte state push (no equality
 * check): copy lbl_803DD990 to lbl_803DBC08 and write new value. */
void titleScreenFn_801368c4(u8 arg);

/* EN v1.0 0x80138EF8  size: 28b  Set bit 0x80000000 of obj->_b8->_54
 * and store lbl_803E2408 into obj->_b8->_808. */
void trickyImpress(u8* obj);

extern void* lbl_803DD984;
extern void* lbl_803DD980;
extern f32 lbl_803DD97C;
extern f32 lbl_803E22E0;
extern u16 lbl_803DD994;
extern u16 lbl_803DD996;
extern u16 lbl_803DD998;
extern s16 lbl_803DD9A8;
extern int getCurUiDll(void);

/* EN v1.0 0x80134808  size: 44b  Release two buffer slots in sequence:
 * textureFree(lbl_803DD984) then textureFree(lbl_803DD980). */
void WarpstoneUI_release(void);

/* EN v1.0 0x801347A4  size: 100b  Per-frame integrator with clamp.
 * Adds (or subtracts, when warpstoneUIState != 0) lbl_803E22D8*timeDelta
 * to lbl_803DD97C, then clamps to [lbl_803E22E0, lbl_803E22DC]. */
extern f32 lbl_803E22D8;
extern f32 lbl_803E22DC;
extern f32 timeDelta;
#pragma scheduling off
int WarpstoneUI_frameStart(void);
#pragma scheduling reset

/* EN v1.0 0x80134834  size: 60b  Acquire two buffer slots and prime
 * the float at lbl_803DD97C with the constant from lbl_803E22E0. */
#pragma scheduling off
void WarpstoneUI_initialise(void);
#pragma scheduling reset

/* EN v1.0 0x80134BC4  size: 32b  Reset the per-frame state group:
 * latch showCredits = 1 and zero five halfword/byte counters. */
#pragma scheduling off
void creditsStart(void);
#pragma scheduling reset

/* EN v1.0 0x80134BE8  size: 60b  Predicate. Returns 1 when the value
 * from getCurUiDll is in {2..6} or equals 7, else 0. */
int gameTextFn_80134be8(void);

/* EN v1.0 0x80133934  size: 52b  Release-and-clear pair: when
 * minimapTexture is non-null, release via textureFree and zero both
 * minimapTexture and lbl_803DD92C. */
void fn_80133934(void);

/* EN v1.0 0x801375A0  size: 40b  Reset debug log/print state: rewind
 * debugLogEnd to the start of the buffer and reload the print x/y
 * coordinates from saved values. */
extern u32 lbl_803DDA00;
extern u32 lbl_803DDA08;
extern u16 debugPrintXpos;
extern u16 debugPrintYpos;
#pragma scheduling off
#pragma peephole off
void fn_801375A0(void);
#pragma peephole reset
#pragma scheduling reset

/* EN v1.0 0x80138908  size: 24b  Bit setter at bit 6 (0x40) of obj->_b8->_58.
 * 83% -- target has a leading `clrlwi r4,r4,24` that MWCC elides since
 * the rlwimi only uses bit 0 of r4. No C form found to force it. */
void fn_80138908(int* obj, u8 v);

/* EN v1.0 0x80135BF0  size: 60b  titlescreen_free: if obj->_46 == 0x77d,
 * trigger Music_Trigger(0x3a, 0) and clear showCredits. */
extern void Music_Trigger(s32 triggerId, s32 mode);

void titlescreen_free(u8* obj);

/* EN v1.0 0x801388D0  size: 56b  Stash 4 args to four globals and resume
 * the thread at &lbl_803AB118. */
extern u8 lbl_803AB118[];
extern s16 lbl_803DDA40;
extern u32 lbl_803DDA3C;
extern u32 lbl_803DDA38;
extern u32 lbl_803DDA34;
extern void OSResumeThread(u8 * thread);
#pragma scheduling off
void fn_801388D0(s16 a, u32 b, u32 c, u32 d);
#pragma scheduling reset

/* EN v1.0 0x801334E0  size: 60b  Gate: when lbl_803DD944 == 2 (s8 compare)
 * and lbl_803DBBB0 != 0, latch lbl_803DD928 = 5 and return 1; else
 * return 0 without touching the latch. */
#pragma peephole off
#pragma scheduling off
u8 fn_801334E0(void);
#pragma scheduling reset
#pragma peephole reset

extern void OSSetErrorHandler(int kind, void* handler);
extern void OSCreateThread(u8* thread, void* entry, void* arg, void* stack_top, int stack_size, int prio, int flags);
extern void fn_80137DF8(void);
extern u8 lbl_803AB428[];
#pragma scheduling off
void fn_80137D28(void);
#pragma scheduling reset

#pragma scheduling off
int trickyFindNearestUsableBaddie(int p1, f32 maxRadius, int p2);
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_80138D7C(int obj, int p2);
#pragma peephole reset
#pragma scheduling reset

extern void ObjModel_SetBlendChannelTargets(int model, int channel, int p3, int p4, f32 weight, int p6);
extern void ObjModel_SetBlendChannelWeight(int model, int channel, f32 weight);
extern f32 lbl_803E23DC;
extern f32 lbl_803E23E0;
extern f32 lbl_803E23E4;
extern f32 lbl_803E23EC;
extern f32 lbl_803E23F0;
extern f32 lbl_803E23F4;
extern f32 lbl_803E23F8;

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
void Tricky_updateBlendChannelWeight(int obj, u8* state);
#pragma peephole reset
#pragma scheduling reset

extern f32 lbl_803DD99C;
extern u8 lbl_803DD9A0;
extern f32 lbl_803E231C;
extern f32 lbl_803E2320;
extern f32 lbl_803E2324;

#pragma scheduling off
#pragma peephole off
void titleScreenShowCopyright(u8 arg);

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

typedef union
{
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
void titleScreenTextDrawFunc(int x0, int y0, int x1, int y1, f32 u0, f32 v0, f32 u1, f32 v1);
#pragma peephole reset
#pragma scheduling reset


#pragma scheduling off
#pragma peephole off
void nameEntryTextDrawFunc(int x0, int y0, int x1, int y1, f32 u0, f32 v0, f32 u1, f32 v1);
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_801343CC(u8* src, u8* dst, u8* ids, int count, int* out);
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
extern u8 lbl_803A9F50[0x48];
extern void Sfx_StopFromObject(int obj, int id);
void fn_80134870(int obj, u8* arr);

/* EN v1.0 0x80135CC8  size: 2784b  titlescreen_update: drive the title
 * screen actor anim state machine, the per-actor footstep/voice sfx flag
 * grid at lbl_803A9F50, the random blink blend, and the one-shot envfx/sky
 * setup. */
#pragma scheduling off
#pragma peephole off
void titlescreen_update(u8* obj);
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_80134870(int obj, u8* arr);
#pragma peephole reset
#pragma scheduling reset

typedef struct
{
    u8 s0 : 2;
    u8 s1 : 2;
    u8 s2 : 2;
    u8 s3 : 2;
} AnimSlots;

#pragma scheduling off
#pragma peephole off
void objAnimFreeChildren(int a, int b, void** c);
#pragma peephole reset
#pragma scheduling reset

extern u16 lbl_803DBC0A;
extern u8 lbl_803DB411;
extern int loadUiDll(int dllId);
extern void TitleMenu_setSelection(int sel);
extern void streamFn_8000a380(int a, int b, int c);
extern void gameTextFn_80016810(int textId, int a, int b);

typedef struct
{
    u16 a;
    u16 b;
} CreditEntry;

extern CreditEntry gCreditEntries[];

#pragma scheduling off
#pragma peephole off
void creditsStart_(void);
#pragma peephole reset

extern void CMenu_SetFadeCounter(int v);
extern int lbl_803DD978;
extern int lbl_803DBBF8;
extern int lbl_803DBBFC;
extern int lbl_803DBC00;
extern int lbl_803DBC04;

typedef struct
{
    s16 bit;
    u8 b2;
    u8 b3;
} WarpstoneEntry;

extern u8 lbl_8031CC50[];
extern u8 lbl_803A9DD0[];
extern WarpstoneEntry lbl_8031CC38[];
extern int lbl_803A9F38[];
extern int* gTitleMenuLinkInterface;

void WarpstoneUI_showUI(int param_1);

typedef struct
{
    u16 t0;
    u16 t1;
    u16 t2;
    u16 t3;
    u8 pad8[3];
    u8 alpha;
    f32 y;
} CreditsLine;

typedef struct
{
    CreditsLine lines[9];
    u16 f90;
    u16 f92;
    u8 count;
    u8 pad95[3];
} CreditsPage;

extern CreditsPage gCreditsPages[];
extern f32 lbl_803E22AC;
extern f32 lbl_803E22B0;
extern f32 lbl_803E22B4;
extern f32 lbl_803E22B8;

#pragma peephole off
int Credits_frameStart(void);
#pragma peephole reset

extern u32 lbl_803E2200;
extern f32 lbl_803DD94C;
extern f32 lbl_803E2260;
extern f32 lbl_803E2264;
extern f32 lbl_803E2268;
extern f32 lbl_803E226C;
extern f32 lbl_803E2270;
extern f32 lbl_803E2274;

#pragma peephole off
void fn_8013351C(void);
#pragma peephole reset

extern u8 enableDebugText;
extern u16* debugDrawFrameBuffer;
extern void DCStoreRange(void* p, u32 nBytes);

#pragma peephole off
void fn_80137A00(int p1, int p2, u8* grid, int p4);
#pragma peephole reset

extern u16* externalFrameBuffer1;
extern u16* externalFrameBuffer0;
extern u8 lbl_8031D060[];

void debugPrintfxy(int x, int y, char* fmt, ...);

extern void selectTexture(char* tex, int slot);
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

int fn_80136A40(int p1, int c);

extern int getButtonsHeld(int p);
extern int getButtonsJustPressed(int p);
extern f32 powfCoreFast(f32 base, f32 exp);
extern int ObjGroup_FindNearestObject(int type, int obj, f32* distOut);
extern s16* Camera_GetCurrentViewSlot(void);
extern int getAngle(f32 dx, f32 dz);
extern u8 lbl_803DD945;
extern u8 lbl_803DD929;
extern s8 lbl_803DBBB1;
extern int lbl_803DBBE8;
extern f32 lbl_803DBBD4;
extern f32 lbl_803DBBD8;
extern f32 lbl_803DBBDC;
extern f32 lbl_803DBBE0;
extern f32 lbl_803DBBE4;
extern f32 lbl_803E2294;
extern f32 lbl_803E2298;
extern f32 lbl_803E229C;

#pragma peephole off
void fn_8013396C(void);
#pragma peephole reset

extern void GXSetTevColor(int id, int* color);
extern void setTextColor(int p);
extern u16 lbl_803DDA14;
extern u16 lbl_803DDA16;
extern u16 lbl_803DBC10;
extern u8 lbl_803DD9F0;
extern u8 lbl_803DD9F1;
extern u8 lbl_803DD9F2;
extern u8 lbl_803DD9F3;
extern u16 lbl_803DD9F6;
extern int lbl_803DDA10;

#pragma peephole off
int fn_80136E00(int p1, u8* p);
#pragma peephole reset

extern void drawScaledTexture(char* tex, f32 x, f32 y, int alpha, int s, int w, int h, int mode);
extern s16 fn_80130124(void);
extern u8 lbl_803DD9C0;
extern f32 lbl_803E22F0;
extern f32 lbl_803E22F4;
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

#pragma peephole off
void gameTextBoxFn_80134d40(int p1, int p2, u32 p3);
#pragma peephole reset

extern u16* debugFrameBuffer;
extern char lbl_803DBC18;
extern char lbl_803DBC1C;
extern char lbl_803DBC20;
extern char lbl_803DBC28;
extern char lbl_803DBC30;
extern char lbl_803DBC34;
extern int OSDisableInterrupts(void);
extern void OSRestoreInterrupts(int level);
extern void VISetPreRetraceCallback(void* cb);
extern void VISetPostRetraceCallback(void* cb);
extern void GXSetBreakPtCallback(void* cb);
extern void __GXAbortWaitPECopyDone(void);
extern void VISetNextFrameBuffer(void* fb);
extern void VIFlush(void);
extern void VIWaitForRetrace(void);

/* EN v1.0 0x80137DF8  size: 2776b  fn_80137DF8: error display thread.
 * Clears the debug framebuffer, prints the exception type, DSISR/SRR0,
 * stack trace and GPR dump via debugPrintfxy, draws the underline and
 * box pixels directly into the framebuffer, and flips buffers forever. */
#pragma peephole off
void fn_80137DF8(void);
#pragma peephole reset

extern u16 lbl_803DD9F4;
extern u32 lbl_803DDA04;
extern u32 lbl_803DD9FC;

/* EN v1.0 0x801375C8  size: 736b  debugPrintDraw: lay out the debug log
 * twice (measure pass then draw pass), drawing the backing rect between
 * the passes when the log produced any extent. */
#pragma peephole off
void debugPrintDraw(int ctx);
#pragma peephole reset
