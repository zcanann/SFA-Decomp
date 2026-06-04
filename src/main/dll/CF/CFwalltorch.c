#include "ghidra_import.h"
#include "main/dll/CF/CFwalltorch.h"

extern undefined8 FUN_80006724();
extern undefined8 FUN_80006824();
extern undefined8 GameBit_Set(int eventId,int value);
extern undefined4 FUN_80041ff8();
extern undefined8 FUN_800427c8();
extern undefined8 FUN_80042800();
extern undefined4 FUN_80042b9c();
extern undefined4 FUN_80042bec();
extern int FUN_80044404();
extern undefined4 FUN_80053b3c();
extern undefined8 FUN_80053c98();
extern undefined8 FUN_8005d17c();
extern undefined4 FUN_80080f28();
extern undefined8 FUN_80080f3c();
extern void warpPadFn_8019042c(int obj);
extern uint FUN_80286840();
extern undefined4 FUN_8028688c();

extern undefined4* DAT_803dd72c;
extern f32 FLOAT_803e4b30;

/*
 * --INFO--
 *
 * Function: Transporter_SeqFn
 * EN v1.0 Address: 0x80190BD4
 * EN v1.0 Size: 4684b
 * EN v1.1 Address: 0x80191150
 * EN v1.1 Size: 2252b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern void Sfx_PlayFromObject(int* obj, int soundId);
extern void unlockLevel(int a, int b, int c);
extern void lockLevel(int dirIdx, int v);
extern int mapGetDirIdx(int mapId);
extern void loadMapAndParent(int mapId);
extern void setLoadedFileFlags_blocks1(void);
extern void clearLoadedFileFlags_blocks1(void);
extern void warpToMap(int warpId, int p2);
extern void getEnvfxActImmediately(int* a, int* b, int id, int p4);
extern void setDrawCloudsAndLights(int v);
extern void skyFn_80088c94(int a, int b);
extern void skyFn_80088e54(int mode, f32 brightness);
extern void timeOfDayFn_80055000(void);
extern int* gMapEventInterface;
extern f32 lbl_803E3E98;

#pragma peephole off
#pragma scheduling off
int Transporter_SeqFn(int* obj, int p2, u8* seq)
{
    int i;
    int* setup = *(int**)((char*)obj + 0x4c);
    u8* state = *(u8**)((char*)obj + 0xb8);
    int id;

    for (i = 0; i < *(u8*)(seq + 0x8b); i++) {
        switch (seq[i + 0x81]) {
        case 7:
            state[0xe] = state[0xe] | 4;
            Sfx_PlayFromObject(obj, 0x420);
            break;
        case 2:
            id = *(int*)((char*)setup + 0x14);
            switch (id) {
            case 0x49c33:
                GameBit_Set(0x884, 1);
                ((void(*)(int,int,int))((void**)*gMapEventInterface)[20])(7, 0, 1);
                ((void(*)(int,int,int))((void**)*gMapEventInterface)[20])(7, 2, 1);
                ((void(*)(int,int,int))((void**)*gMapEventInterface)[20])(7, 3, 1);
                ((void(*)(int,int,int))((void**)*gMapEventInterface)[20])(7, 7, 1);
                ((void(*)(int,int,int))((void**)*gMapEventInterface)[20])(7, 10, 1);
                ((void(*)(int,int,int))((void**)*gMapEventInterface)[20])(10, 7, 0);
                /* fallthrough */
            case 0x48506:
            case 0x4977d:
                loadMapAndParent(7);
                unlockLevel(0, 0, 1);
                lockLevel(mapGetDirIdx(7), 1);
                break;
            case 0x43f83:
                loadMapAndParent(0x21);
                lockLevel(mapGetDirIdx(0x21), 1);
                break;
            case 0x4a533:
                loadMapAndParent(0x28);
                lockLevel(mapGetDirIdx(0x28), 1);
                break;
            case 0xc5d:
                unlockLevel(mapGetDirIdx(0x21), 1, 0);
                break;
            case 0x47064:
                loadMapAndParent(0x1c);
                lockLevel(mapGetDirIdx(0x1c), 1);
                lockLevel(mapGetDirIdx(0x1b), 0);
                break;
            case 0x4800c:
                loadMapAndParent(0x22);
                lockLevel(mapGetDirIdx(0xd), 0);
                lockLevel(mapGetDirIdx(0x22), 1);
                break;
            case 0x48018:
                unlockLevel(mapGetDirIdx(0x22), 1, 0);
                GameBit_Set(0x36a, 0);
                ((void(*)(int,int,int))((void**)*gMapEventInterface)[20])(0xd, 0, 1);
                ((void(*)(int,int,int))((void**)*gMapEventInterface)[20])(0xd, 1, 1);
                ((void(*)(int,int,int))((void**)*gMapEventInterface)[20])(0xd, 5, 1);
                ((void(*)(int,int,int))((void**)*gMapEventInterface)[20])(0xd, 10, 1);
                ((void(*)(int,int,int))((void**)*gMapEventInterface)[20])(0xd, 0xb, 1);
                GameBit_Set(0xe05, 0);
                break;
            case 0x45dd6:
                unlockLevel(0, 0, 1);
                lockLevel(mapGetDirIdx(4), 0);
                break;
            case 0x2ba7:
                unlockLevel(0, 0, 1);
                lockLevel(mapGetDirIdx(0x12), 0);
                lockLevel(mapGetDirIdx(0x1f), 1);
                loadMapAndParent(0x1f);
                break;
            case 0x46a40:
                unlockLevel(0, 0, 1);
                lockLevel(mapGetDirIdx(0xe), 0);
                lockLevel(mapGetDirIdx(0x20), 1);
                loadMapAndParent(0x20);
                break;
            case 0x4b666:
                unlockLevel(0, 0, 1);
                lockLevel(mapGetDirIdx(0x32), 0);
                lockLevel(mapGetDirIdx(0x15), 1);
                loadMapAndParent(0x15);
                break;
            case 0x497f4:
                unlockLevel(0, 0, 1);
                lockLevel(mapGetDirIdx(10), 0);
                lockLevel(mapGetDirIdx(0x27), 1);
                loadMapAndParent(0x27);
                break;
            case 0x4cde6:
                unlockLevel(0, 0, 1);
                lockLevel(mapGetDirIdx(10), 0);
                break;
            }
            break;
        case 3:
            switch (*(int*)((char*)setup + 0x14)) {
            case 0x47064:
                unlockLevel(0, 0, 1);
                break;
            }
            break;
        case 5:
            switch (*(int*)((char*)setup + 0x14)) {
            case 0x47064:
                setLoadedFileFlags_blocks1();
                break;
            }
            break;
        case 6:
            switch (*(int*)((char*)setup + 0x14)) {
            case 0x47064:
                clearLoadedFileFlags_blocks1();
                break;
            }
            break;
        case 1:
            switch (*(int*)((char*)setup + 0x14)) {
            case 0x47064:
                clearLoadedFileFlags_blocks1();
                break;
            }
            warpToMap(*(s8*)((char*)setup + 0x1a), 0);
            break;
        case 8:
            id = *(int*)((char*)setup + 0x14);
            switch (id) {
            case 0x43f83:
            case 0x4977d:
                getEnvfxActImmediately(obj, obj, 0x224, 0);
                getEnvfxActImmediately(obj, obj, 0x223, 0);
                getEnvfxActImmediately(obj, obj, 0x22e, 0);
                getEnvfxActImmediately(obj, obj, 0x218, 0);
                setDrawCloudsAndLights(0);
                skyFn_80088c94(1, 1);
                skyFn_80088e54(0, lbl_803E3E98);
                break;
            case 0x48506:
            case 0x4a533:
                getEnvfxActImmediately(obj, obj, 0x217, 0);
                getEnvfxActImmediately(obj, obj, 0x216, 0);
                getEnvfxActImmediately(obj, obj, 0x22e, 0);
                getEnvfxActImmediately(obj, obj, 0x218, 0);
                setDrawCloudsAndLights(1);
                getEnvfxActImmediately(obj, obj, 0x84, 0);
                getEnvfxActImmediately(obj, obj, 0x8a, 0);
                skyFn_80088c94(1, 0);
                skyFn_80088e54(0, lbl_803E3E98);
                break;
            case 0x4b666:
                getEnvfxActImmediately(obj, obj, 0x23a, 0);
                getEnvfxActImmediately(obj, obj, 0x23b, 0);
                break;
            case 0x4b667:
                getEnvfxActImmediately(obj, obj, 0x23a, 0);
                getEnvfxActImmediately(obj, obj, 0x23b, 0);
                ((void(*)(int,int,int))((void**)*gMapEventInterface)[20])(0x15, 2, 1);
                getEnvfxActImmediately(0, 0, 0x23e, 0);
                skyFn_80088e54(1, lbl_803E3E98);
                break;
            case 0x4670d:
            case 0x4827e:
            case 0x49267:
                getEnvfxActImmediately(obj, obj, 0x247, 0);
                getEnvfxActImmediately(obj, obj, 0x248, 0);
                timeOfDayFn_80055000();
                GameBit_Set(0xef6, 1);
                break;
            case 0x4cb6a:
                getEnvfxActImmediately(obj, obj, 0x238, 0);
                getEnvfxActImmediately(obj, obj, 0x239, 0);
                skyFn_80088c94(1, 1);
                skyFn_80088e54(0, lbl_803E3E98);
                /* fallthrough */
            case 0x4cb84:
                GameBit_Set(0xef6, 0);
                break;
            }
            break;
        }
    }
    warpPadFn_8019042c((int)obj);
    return 0;
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: transporter_getExtraSize
 * EN v1.0 Address: 0x801914A0
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80191640
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int transporter_getExtraSize(void)
{
  return 0x10;
}

extern void objRenderFn_80041018(int obj);
extern uint GameBit_Get(int eventId);
extern void warpPadPlayerStandingOn(int obj);
extern short lbl_803DCEB8;

/*
 * --INFO--
 *
 * Function: transporter_update
 * EN v1.0 Address: 0x80191658
 * EN v1.0 Size: 72b
 */
#pragma peephole off
#pragma scheduling off
void transporter_update(int obj)
{
    register int self = obj;
    register int state2 = *(int *)(self + 0x4c);
    if ((int)(signed char)*(u8 *)(state2 + 0x1a) != -1) {
        warpPadPlayerStandingOn(self);
    }
    warpPadFn_8019042c(self);
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: transporter_hitDetect
 * EN v1.0 Address: 0x801914AC
 * EN v1.0 Size: 428b
 */
#pragma peephole off
#pragma scheduling off
void transporter_hitDetect(int obj)
{
    register int self = obj;
    register int state2 = *(int *)(self + 0x4c);
    register int state = *(int *)(self + 0xb8);

    if ((int)lbl_803DCEB8 > -1) {
        *(u8 *)(self + 0xaf) = (u8)((u32)*(u8 *)(self + 0xaf) & 0xffffffe7);
        *(u8 *)(state + 0xe) = (u8)((u32)*(u8 *)(state + 0xe) | 1);
        if (*(u32 *)(self + 0x74) != 0) {
            objRenderFn_80041018(self);
        }
        return;
    }

    if ((int)(signed char)*(u8 *)(state2 + 0x1a) != -1
        && (*(u8 *)(state + 0xe) & 0x20) == 0) {
        if (*(u8 *)(state + 0xd) != 0 || *(u8 *)(state + 0xc) != 0) {
            *(u8 *)(self + 0xaf) = (u8)((u32)*(u8 *)(self + 0xaf) | 0x8);
            *(u8 *)(state + 0xe) = (u8)((u32)*(u8 *)(state + 0xe) & ~1);
        } else if ((int)*(short *)(state2 + 0x20) != -1
                   && GameBit_Get((int)*(short *)(state2 + 0x20)) == 0) {
            *(u8 *)(self + 0xaf) = (u8)((u32)*(u8 *)(self + 0xaf) & 0xfffffff7);
            *(u8 *)(self + 0xaf) = (u8)((u32)*(u8 *)(self + 0xaf) | 0x10);
            *(u8 *)(state + 0xe) = (u8)((u32)*(u8 *)(state + 0xe) & ~1);
        } else {
            *(u8 *)(self + 0xaf) = (u8)((u32)*(u8 *)(self + 0xaf) & 0xffffffe7);
            *(u8 *)(state + 0xe) = (u8)((u32)*(u8 *)(state + 0xe) | 1);
        }
        if (*(u32 *)(self + 0x74) != 0) {
            objRenderFn_80041018(self);
        }
        return;
    }

    /* Branch C */
    if ((*(u8 *)(state + 0xe) & 0x40) != 0) {
        *(u8 *)(self + 0xaf) = (u8)((u32)*(u8 *)(self + 0xaf) | 0x8);
    } else {
        *(u8 *)(self + 0xaf) = (u8)((u32)*(u8 *)(self + 0xaf) & 0xfffffff7);
        *(u8 *)(self + 0xaf) = (u8)((u32)*(u8 *)(self + 0xaf) | 0x10);
    }
    *(u8 *)(state + 0xe) = (u8)((u32)*(u8 *)(state + 0xe) & ~1);
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: transporter_render
 * EN v1.0 Address: 0x801914A8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80191648
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void transporter_render(void)
{
}
