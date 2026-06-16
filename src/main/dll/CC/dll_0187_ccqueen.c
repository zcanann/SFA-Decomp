/*
 * ccqueen - CloudRunner Queen object (DLL 0x0187). The Queen in the
 * Crystal Caves throne room. Once the gas puzzle is done (gameBit 0xA3) and
 * the player gets close she latches gameBit 0x1C2; gameBit 0x1C3 retires
 * her (hidden + hits disabled). Otherwise she advances her current move,
 * runs the shared character think routine (dll_2E_func03) and plays eye
 * anims. The large extra block (0x654 bytes) is the shared character state
 * driven by the dll_2E_func* helpers.
 */
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/objseq.h"

extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern void objRenderFn_8003b8f4(f32);
extern f32 timeDelta;
extern undefined4 ObjHits_DisableObject();
extern undefined4 dll_2E_func03();
extern void dll_2E_func06(int* obj, void* state, int flags);
extern void dll_2E_func05(int* obj, u8* sub, int a, int b, int c);
extern void dll_2E_func08(u8* sub, int a, int b);
extern void dll_2E_func09(u8* sub, void* a, void* b, int c);
extern void* Obj_GetPlayerObject(void);
extern f32 vec3f_distanceSquared(f32 * p1, f32 * p2);
extern void characterDoEyeAnims(int obj, void* p);

extern f32 lbl_803E4660; /* render scale */
extern f32 lbl_803E4664; /* squared trigger distance */
extern f32 lbl_803E4668; /* move advance rate */

typedef struct
{
    s16 v[3];
} _S16x3;

extern _S16x3 lbl_803E4650;
extern _S16x3 lbl_803E4658;

int ccqueen_getExtraSize(void) { return 0x654; }

void ccqueen_render(int* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    void* state = ((GameObject*)obj)->extra;
    objRenderFn_8003b8f4(lbl_803E4660);
    dll_2E_func06(obj, state, 0);
}

#pragma scheduling off
#pragma peephole off
void ccqueen_init(int* obj, u8* def)
{
    u8* sub;
    _S16x3 buf2;
    _S16x3 buf1;
    sub = ((GameObject*)obj)->extra;
    buf2 = lbl_803E4650;
    buf1 = lbl_803E4658;
    ((GameObject*)obj)->anim.rotX = (s16)(def[0x1a] << 8);
    dll_2E_func05(obj, sub, 0x71c7, 0x3555, 3);
    dll_2E_func08(sub, 0x258, 0xf0);
    dll_2E_func09(sub, &buf1, &buf2, 3);
    sub[0x611] = (u8)(sub[0x611] | 0xa);
}

void ccqueen_update(int* obj)
{
    u8* sub;
    int* player;

    sub = ((GameObject*)obj)->extra;
    if (GameBit_Get(0x1c2) == 0 && GameBit_Get(0xa3) != 0)
    {
        player = (int*)Obj_GetPlayerObject();
        if (vec3f_distanceSquared(&((GameObject*)obj)->anim.worldPosX, &((GameObject*)player)->anim.worldPosX) <
            lbl_803E4664)
        {
            GameBit_Set(0x1c2, 1);
        }
    }
    if (GameBit_Get(0x1c3) != 0)
    {
        ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags | OBJANIM_FLAG_HIDDEN);
        ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x8000);
        ObjHits_DisableObject(obj);
    }
    else
    {
        ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)((int)obj, lbl_803E4668, timeDelta, NULL);
        dll_2E_func03(obj, sub);
        characterDoEyeAnims((int)obj, sub + 0x624);
    }
}
