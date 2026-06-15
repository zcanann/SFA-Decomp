#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"

typedef struct Dll2A4State
{
    u8 pad0[0x4 - 0x0];
    s16 unk4;
    s16 unk6;
    s16 unk8;
    u8 padA[0x10 - 0xA];
} Dll2A4State;


int dll_2A4_getExtraSize_ret_12(void) { return 0xc; }

int dll_2A4_getObjectTypeId(void) { return 0x0; }

void dll_2A4_free_nop(void)
{
}

void dll_2A4_hitDetect_nop(void)
{
}

void dll_2A4_release_nop(void)
{
}

void dll_2A4_initialise_nop(void)
{
}

void dll_2A4_render(int obj, int p2, int p3, int p4, int p5)
{
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E7138);
}

void dll_2A4_update(int obj)
{
    int state = *(int*)&((GameObject*)obj)->extra;

    if (*(f32*)state > lbl_803E713C)
    {
        *(f32*)state -= timeDelta;
        if (*(f32*)state <= lbl_803E713C)
        {
            *(f32*)state = lbl_803E713C;
            Obj_FreeObject(obj);
            return;
        }
    }

    ((GameObject*)obj)->anim.rotX = (s16)((f32) * (s16*)(state + 4) * timeDelta + (f32) * (s16*)(obj + 0));
    ((GameObject*)obj)->anim.rotY = (s16)((f32) * (s16*)(state + 6) * timeDelta + (f32) * (s16*)(obj + 2));
    ((GameObject*)obj)->anim.rotZ = (s16)((f32) * (s16*)(state + 8) * timeDelta + (f32) * (s16*)(obj + 4));

    objMove(obj, ((GameObject*)obj)->anim.velocityX * timeDelta, ((GameObject*)obj)->anim.velocityY * timeDelta,
            ((GameObject*)obj)->anim.velocityZ * timeDelta);
}

void dll_2A4_init(int obj)
{
    int state = *(int*)&((GameObject*)obj)->extra;

    ((GameObject*)obj)->anim.rotX = randomGetRange(0, 0xffff);
    ((GameObject*)obj)->anim.rotY = randomGetRange(0, 0xffff);
    ((GameObject*)obj)->anim.rotZ = randomGetRange(0, 0xffff);
    ((Dll2A4State*)state)->unk4 = randomGetRange(-0x14, 0x14);
    ((Dll2A4State*)state)->unk6 = randomGetRange(-0x14, 0x14);
    ((Dll2A4State*)state)->unk8 = randomGetRange(-0x14, 0x14);
}

void fn_802315EC(int obj, ARWGeneratorState* state, ARWGeneratorSetup* setup)
{
    int newObj;
    f32 dir[3];

    if (Obj_IsLoadingLocked())
    {
        newObj = Obj_AllocObjectSetup(0x20, 0x616);
        *(f32*)(newObj + 8) = ((GameObject*)obj)->anim.localPosX + (f32)(int)
        randomGetRange(-*(s8*)&setup->spreadX, *(s8*)&setup->spreadX);
        *(f32*)(newObj + 0xc) = ((GameObject*)obj)->anim.localPosY + (f32)(int)
        randomGetRange(-*(s8*)&setup->spreadY, *(s8*)&setup->spreadY);
        *(f32*)(newObj + 0x10) = ((GameObject*)obj)->anim.localPosZ + (f32)(int)
        randomGetRange(-*(s8*)&setup->spreadZ, *(s8*)&setup->spreadZ);
        *(u8*)(newObj + 0x1a) = 0;
        *(u8*)(newObj + 0x19) = 0;
        *(u8*)(newObj + 0x18) = 0;
        *(u8*)(newObj + 4) = 1;
        *(u8*)(newObj + 5) = 1;
        newObj = ((int (*)(int, int))loadObjectAtObject)(obj, newObj);
        dir[0] = (f32)setup->velocityX / lbl_803E7140;
        dir[1] = (f32)setup->velocityY / lbl_803E7140;
        dir[2] = (f32)setup->velocityZ / lbl_803E7140;
        fn_8023137C(newObj, (int)dir);
        fn_8023134C(newObj, setup->projectileSpeed);
    }
}

void fn_802317A8(int obj, ARWGeneratorState* state, ARWGeneratorSetup* setup)
{
    int newObj;
    f32 dir[3];

    if (Obj_IsLoadingLocked())
    {
        newObj = Obj_AllocObjectSetup(0x20, 0x617);
        *(f32*)(newObj + 8) = ((GameObject*)obj)->anim.localPosX + (f32)(int)
        randomGetRange(-*(s8*)&setup->spreadX, *(s8*)&setup->spreadX);
        *(f32*)(newObj + 0xc) = ((GameObject*)obj)->anim.localPosY + (f32)(int)
        randomGetRange(-*(s8*)&setup->spreadY, *(s8*)&setup->spreadY);
        *(f32*)(newObj + 0x10) = ((GameObject*)obj)->anim.localPosZ + (f32)(int)
        randomGetRange(-*(s8*)&setup->spreadZ, *(s8*)&setup->spreadZ);
        *(u8*)(newObj + 0x1a) = 0;
        *(u8*)(newObj + 0x19) = 0;
        *(u8*)(newObj + 0x18) = 0;
        *(u8*)(newObj + 4) = 1;
        *(u8*)(newObj + 5) = 1;
        newObj = ((int (*)(int, int))loadObjectAtObject)(obj, newObj);
        dir[0] = (f32)setup->velocityX / lbl_803E7140;
        dir[1] = (f32)setup->velocityY / lbl_803E7140;
        dir[2] = (f32)setup->velocityZ / lbl_803E7140;
        fn_80231058(newObj, (int)dir);
        fn_80231028(newObj, setup->projectileSpeed);
    }
}
