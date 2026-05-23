#include "ghidra_import.h"
#include "main/objanim.h"

/* Pattern wrappers. */
extern byte framesThisStep;
extern int lbl_803DC380;
extern f32 lbl_803E6BB0;
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern int *objFindTexture(int obj, int textureIndex, int materialIndex);
extern void mm_free(void *ptr);
extern int GameBit_Get(int id);
extern void Obj_FreeObject(int obj);

int drenergydisc_getExtraSize(void) { return 1; }
int drenergydisc_getObjectTypeId(void) { return 0; }
void drenergydisc_free(void) {}
void drenergydisc_render(void) {}
void drenergydisc_hitDetect(void) {}

void drenergydisc_update(int obj)
{
    int *texture;
    int state = *(int *)(obj + 0xb8);
    int setup = *(int *)(obj + 0x4c);

    if (GameBit_Get(*(s16 *)(setup + 0x20)) != 0) {
        if ((*(s8 *)state) >= 0) {
            *(u8 *)state |= 0x80;
            Sfx_PlayFromObject(obj, 0x30c);
        }

        texture = objFindTexture(obj, 0, 0);
        if (texture != NULL) {
            *texture = 0x100;
        }

        texture = objFindTexture(obj, 0, 0);
        if (texture != NULL) {
            *(s16 *)((char *)texture + 0xa) =
                *(s16 *)((char *)texture + 0xa) + (s16)(lbl_803DC380 * framesThisStep);
            if (*(s16 *)((char *)texture + 0xa) < -0x1000) {
                *(s16 *)((char *)texture + 0xa) = 0;
            }
        }
    }

    if (GameBit_Get(*(s16 *)(setup + 0x1e)) != 0) {
        ObjAnim_SetCurrentMove(obj, 0, lbl_803E6BB0, 0);
    }
}

void drenergydisc_init(int obj, int setup)
{
    int *texture;
    int state = *(int *)(obj + 0xb8);

    *(s16 *)obj = (s16)((s8)*(u8 *)(setup + 0x18) << 8);
    if (GameBit_Get(*(s16 *)(setup + 0x20)) != 0) {
        *(u8 *)state |= 0x80;
        Sfx_PlayFromObject(obj, 0x30c);
        texture = objFindTexture(obj, 0, 0);
        if (texture != NULL) {
            *texture = 0x100;
        }
    } else {
        *(u8 *)state &= 0x7f;
        texture = objFindTexture(obj, 0, 0);
        if (texture != NULL) {
            *texture = 0;
        }
    }
    *(u16 *)(obj + 0xb0) |= 0x6000;
}

void drenergydisc_release(void) {}
void drenergydisc_initialise(void) {}

int drlightbea_getExtraSize(void) { return 0xc; }
int drlightbea_getObjectTypeId(void) { return 0; }
void drlightbea_free(int obj)
{
    int state = *(int *)(obj + 0xb8);
    void *buffer = *(void **)state;

    if (buffer != NULL) {
        mm_free(buffer);
        *(void **)state = NULL;
    }
}

void drlightbea_hitDetect(void) {}
void drlightbea_update(int obj)
{
    int state = *(int *)(obj + 0xb8);
    if ((*(u8 *)(state + 4) & 0x40) != 0) {
        Obj_FreeObject(obj);
    }
}

void drlightbea_init(int obj)
{
    int state = *(int *)(obj + 0xb8);
    *(u8 *)(state + 4) &= 0x7f;
    *(void **)state = NULL;
    *(u8 *)(state + 4) &= 0xbf;
}

void drlightbea_release(void) {}
void drlightbea_initialise(void) {}

int fn_80223BBC(void) { return 0x2; }
int fn_80223D10(void) { return 0x2; }
int dll_28B_getExtraSize_ret_2756(void) { return 0xac4; }
int dll_28B_getObjectTypeId(void) { return 0x0; }
void dll_28B_hitDetect_nop(void) {}
void dll_28B_release_nop(void) {}
int dll_299_getExtraSize_ret_2(void) { return 0x2; }
int dll_299_getObjectTypeId(void) { return 0x0; }
void dll_299_render_nop(void) {}
void dll_299_hitDetect_nop(void) {}
void dll_299_release_nop(void) {}
void dll_299_initialise_nop(void) {}
int Dummy29E_getExtraSize(void) { return 0x0; }
int Dummy29E_getObjectTypeId(void) { return 0x0; }
void Dummy29E_free(void) {}
void Dummy29E_render(void) {}
void Dummy29E_hitDetect(void) {}
void Dummy29E_update(void) {}
void Dummy29E_init(void) {}
void Dummy29E_release(void) {}
void Dummy29E_initialise(void) {}
int dll_2A3_getExtraSize_ret_12(void) { return 0xc; }
int dll_2A3_getObjectTypeId(void) { return 0x0; }
void dll_2A3_release_nop(void) {}
void dll_2A3_initialise_nop(void) {}
int dll_2A4_getExtraSize_ret_12(void) { return 0xc; }
int dll_2A4_getObjectTypeId(void) { return 0x0; }
void dll_2A4_free_nop(void) {}
void dll_2A4_hitDetect_nop(void) {}
void dll_2A4_release_nop(void) {}
void dll_2A4_initialise_nop(void) {}
