/*
 * ccqueen - CloudRunner Queen object (DLL 0x0187). The Queen in the
 * Crystal Caves throne room. Once the gas puzzle is done (gameBit 0xA3) and
 * the player gets close she latches gameBit 0x1C2; gameBit 0x1C3 retires
 * her (hidden + hits disabled). Otherwise she advances her current move,
 * runs the shared character think routine (dll_2E_func03) and plays eye
 * anims. The large extra block (0x654 bytes) is the shared character state
 * driven by the dll_2E_func* helpers.
 */
#include "main/game_object.h"
#include "main/gamebits.h"
#include "main/dll/VF/vf_shared.h"

#define CCQUEEN_OBJFLAG_UPDATE_DISABLED 0x8000

extern u32 ObjHits_DisableObject();
extern u32 dll_2E_func03();
extern void dll_2E_func06(int* obj, void* state, int flags);
extern void dll_2E_func05(int* obj, u8* sub, int a, int b, int c);
extern void dll_2E_func08(u8* sub, int a, int b);
extern void dll_2E_func09(u8* sub, void* a, void* b, int c);
extern f32 vec3f_distanceSquared(f32* a, f32* b);
extern void characterDoEyeAnims(int obj, void* p);
extern f32 lbl_803E4660; /* render scale */
extern f32 lbl_803E4664; /* squared trigger distance */
extern f32 lbl_803E4668; /* move advance rate */

#define GAMEBIT_QUEEN_LATCHED 0x1c2   /* player got close once the gas puzzle was done */
#define GAMEBIT_QUEEN_RETIRED 0x1c3   /* queen leaves: hidden + hits disabled */
#define GAMEBIT_GAS_PUZZLE_DONE 0xa3

typedef struct
{
    s16 v[3];
} Vec3s;

STATIC_ASSERT(sizeof(Vec3s) == 0x6);

extern Vec3s lbl_803E4650; /* eye-anim setup vector A */
extern Vec3s lbl_803E4658; /* eye-anim setup vector B */

int ccqueen_getExtraSize(void) { return 0x654; }

void ccqueen_render(int* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    void* state = ((GameObject*)obj)->extra;
    objRenderFn_8003b8f4(lbl_803E4660);
    dll_2E_func06(obj, state, 0);
}

#pragma scheduling off
#pragma peephole off
void ccqueen_init(int* obj, u8* placement)
{
    u8* charState;
    Vec3s buf2;
    Vec3s buf1;
    charState = ((GameObject*)obj)->extra;
    buf2 = lbl_803E4650;
    buf1 = lbl_803E4658;
    ((GameObject*)obj)->anim.rotX = (s16)(placement[0x1a] << 8);
    dll_2E_func05(obj, charState, 0x71c7, 0x3555, 3);
    dll_2E_func08(charState, 0x258, 0xf0);
    dll_2E_func09(charState, &buf1, &buf2, 3);
    charState[0x611] = (u8)(charState[0x611] | 0xa);
}

void ccqueen_update(int* obj)
{
    u8* charState;
    int* player;

    charState = ((GameObject*)obj)->extra;
    if (GameBit_Get(GAMEBIT_QUEEN_LATCHED) == 0 && GameBit_Get(GAMEBIT_GAS_PUZZLE_DONE) != 0)
    {
        player = Obj_GetPlayerObject();
        if (vec3f_distanceSquared(&((GameObject*)obj)->anim.worldPosX, &((GameObject*)player)->anim.worldPosX) <
            lbl_803E4664)
        {
            GameBit_Set(GAMEBIT_QUEEN_LATCHED, 1);
        }
    }
    if (GameBit_Get(GAMEBIT_QUEEN_RETIRED) != 0)
    {
        ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags | OBJANIM_FLAG_HIDDEN);
        ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | CCQUEEN_OBJFLAG_UPDATE_DISABLED);
        ObjHits_DisableObject(obj);
    }
    else
    {
        ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)((int)obj, lbl_803E4668, timeDelta, NULL);
        dll_2E_func03(obj, charState);
        characterDoEyeAnims((int)obj, charState + 0x624);
    }
}
