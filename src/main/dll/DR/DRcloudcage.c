#include "ghidra_import.h"
#include "main/dll/DR/DRcloudcage.h"

extern int Sfx_IsPlayingFromObjectChannel(int obj, int channel);
extern void Sfx_SetObjectChannelVolume(double volume, int obj, int channel, uint volumeByte);
extern int Sfx_PlayFromObject(int obj, int sfxId);
extern int Obj_GetPlayerObject(void);
extern double Vec_distance(int *from, int *to);
extern void fn_8009837C();

extern undefined4* gCheckpointInterface;
extern s32 lbl_803DC0BC;
extern f32 lbl_803DC0E0;
extern f32 timeDelta;
extern f32 lbl_803DDC64;
extern undefined4 lbl_803AD088;
extern f32 lbl_803E5AE8;
extern f32 lbl_803E5AEC;
extern f32 lbl_803E5AF8;
extern f64 lbl_803E5B00;
extern f32 lbl_803E5B08;
extern f32 lbl_803E5B0C;
extern f32 lbl_803E5B10;
extern f32 lbl_803E5B14;
extern f32 lbl_803E5B18;
extern f32 lbl_803E5B1C;
extern f32 lbl_803E5B20;
extern f32 lbl_803E5B24;
extern f32 lbl_803E5B28;
extern f32 lbl_803E5B2C;
extern f32 lbl_803E5B30;
extern f32 lbl_803E5B34;
extern f32 lbl_803E5B38;
extern f32 lbl_803E5B3C;
extern f32 lbl_803E5B40;
extern f32 lbl_803E5B44;
extern f32 lbl_803E5B48;
extern f32 lbl_803E5B4C;
extern f32 lbl_803E5B50;
extern f32 lbl_803E5B54;
extern f32 lbl_803E5B58;
extern f32 lbl_803E5B5C;
extern f32 lbl_803E5B60;
extern f32 lbl_803E5B64;

void fn_801E9C00(int obj, int state)
{
    (void)obj;
    (void)state;
}

void fn_801EA240(double distanceScale, int obj, int state, uint intensity, undefined4 unused,
                 uint channelFlags)
{
    float fVar1;
    uint volumeByte;
    int isPlaying;
    uint signedVolume;
    double dVar6;
    double clampedScale;
    undefined auStack72[8];
    float local_40;
    float local_3c;
    float local_38;
    float local_34;
    double local_30;
    double local_28;

    clampedScale = (double)lbl_803E5AE8;
    if ((clampedScale <= distanceScale) && (clampedScale = distanceScale, (double)lbl_803E5B08 < distanceScale)) {
        clampedScale = (double)lbl_803E5B08;
    }
    if (((channelFlags & 1) != 0) && (isPlaying = Sfx_IsPlayingFromObjectChannel(obj, 8), isPlaying != 0)) {
        lbl_803DDC64 = (float)((double)lbl_803E5B0C * clampedScale);
        if (lbl_803DDC64 < lbl_803E5AE8) {
            lbl_803DDC64 = -lbl_803DDC64;
        }
        if (lbl_803DDC64 < lbl_803E5B10) {
            lbl_803DDC64 = lbl_803E5B10;
        }
        if (lbl_803E5B14 < lbl_803DDC64) {
            lbl_803DDC64 = lbl_803E5B14;
        }
        if (lbl_803E5B18 <= *(float *)(state + 0x424)) {
            volumeByte = 0;
        } else {
            volumeByte = (uint)((double)lbl_803E5B1C * clampedScale);
            local_30 = (double)(longlong)(int)volumeByte;
            if ((int)volumeByte < 0) {
                volumeByte = -volumeByte;
            }
            if (0x7f < (int)volumeByte) {
                volumeByte = 0x7f;
            }
        }
        Sfx_SetObjectChannelVolume((double)(lbl_803E5B20 + lbl_803DDC64 / lbl_803E5B08), obj, 8,
                                   volumeByte & 0xff);
    }
    if ((((channelFlags & 2) != 0) && (isPlaying = Sfx_IsPlayingFromObjectChannel(obj, 1), isPlaying != 0)) &&
        (*(float *)(state + 0x424) < lbl_803E5B18)) {
        dVar6 = (double)lbl_803E5AE8;
        if (dVar6 != clampedScale) {
            local_30 = (double)CONCAT44(0x43300000, (int)*(short *)(obj + 4) ^ 0x80000000);
            dVar6 = (double)((float)(clampedScale * (double)(float)(local_30 - lbl_803E5B00)) /
                             lbl_803E5B24);
        }
        lbl_803DDC64 = (float)dVar6;
        fVar1 = (float)dVar6;
        if (lbl_803E5AE8 <= fVar1) {
            if (lbl_803E5AEC < fVar1) {
                lbl_803DDC64 = lbl_803E5AEC;
            }
        } else {
            lbl_803DDC64 = -fVar1;
        }
        volumeByte = (uint)(lbl_803E5B28 * lbl_803DDC64);
        local_30 = (double)(longlong)(int)volumeByte;
        signedVolume = volumeByte ^ 0x80000000;
        local_28 = (double)CONCAT44(0x43300000, signedVolume);
        if ((float)(local_28 - lbl_803E5B00) <= lbl_803E5B28) {
            local_28 = (double)CONCAT44(0x43300000, signedVolume);
            if ((float)(local_28 - lbl_803E5B00) < lbl_803E5AE8) {
                volumeByte = 0;
            }
        } else {
            volumeByte = 0x7f;
        }
        local_28 = (double)CONCAT44(0x43300000, signedVolume);
        Sfx_SetObjectChannelVolume((double)(lbl_803E5B20 + lbl_803DDC64), obj, 1, volumeByte & 0xff);
    }
    if ((channelFlags & 4) != 0) {
        Sfx_PlayFromObject(obj, *(undefined2 *)(state + 0x440));
        Sfx_PlayFromObject(obj, 0x11b);
        if ((int)intensity < 6) {
            if (lbl_803E5B10 < *(float *)(state + 0x3f8)) {
                *(float *)(state + 0x3f8) =
                    -(lbl_803E5B2C * timeDelta - *(float *)(state + 0x3f8));
            }
        } else {
            *(float *)(state + 0x3f8) = *(float *)(state + 0x3f8) + timeDelta;
        }
        if (lbl_803E5B08 < *(float *)(state + 0x3f8)) {
            *(float *)(state + 0x3f8) = lbl_803E5B08;
        }
        if (*(float *)(state + 0x3f8) < lbl_803E5B30) {
            *(float *)(state + 0x3f8) = lbl_803E5B30;
        }
        isPlaying = (int)*(float *)(state + 0x3f8);
        local_28 = (double)(longlong)isPlaying;
        Sfx_SetObjectChannelVolume((double)(*(float *)(state + 0x3f8) * lbl_803E5B38 + lbl_803E5B34),
                                   obj, 2, isPlaying);
        if ((int)intensity < 6) {
            if (lbl_803E5B3C < *(float *)(state + 0x3f4)) {
                *(float *)(state + 0x3f4) =
                    -(lbl_803E5AF8 * timeDelta - *(float *)(state + 0x3f4));
            }
        } else {
            local_28 = (double)CONCAT44(0x43300000, intensity ^ 0x80000000);
            *(float *)(state + 0x3f4) = lbl_803E5B3C + (float)(local_28 - lbl_803E5B00);
        }
        if (lbl_803E5B40 < *(float *)(state + 0x3f4)) {
            *(float *)(state + 0x3f4) = lbl_803E5B40;
        }
        if (*(float *)(state + 0x3f4) < lbl_803E5B44) {
            *(float *)(state + 0x3f4) = lbl_803E5B44;
        }
        isPlaying = (int)*(float *)(state + 0x3f4);
        local_28 = (double)(longlong)isPlaying;
        Sfx_SetObjectChannelVolume((double)(*(float *)(state + 0x3f4) / lbl_803E5B48), obj, 4,
                                   isPlaying);
        local_3c = lbl_803E5B4C;
        local_38 = lbl_803E5B50;
        local_34 = lbl_803E5B54;
        local_40 = lbl_803E5AE8;
        fn_8009837C((double)lbl_803E5AF8, (double)(*(float *)(state + 0x3f4) / lbl_803E5B58),
                    obj, 2, 0, 1, auStack72);
        local_3c = lbl_803E5B5C;
        fn_8009837C((double)lbl_803E5AF8, (double)(*(float *)(state + 0x3f4) / lbl_803E5B58),
                    obj, 2, 0, 1, auStack72);
    }
    fn_801E9C00(obj, state);
    (void)unused;
}

double fn_801EA678(int obj, int state)
{
    float fVar1;
    float fVar2;
    int iVar3;
    double dVar5;
    double dVar6;
    double dVar7;

    if ((lbl_803DC0BC == -1) ||
        (iVar3 = (**(code **)(*gCheckpointInterface + 0x34))(state + 0x28), iVar3 < lbl_803DC0BC)) {
        if (lbl_803DC0BC == -1) {
            iVar3 = Obj_GetPlayerObject();
            dVar5 = (double)Vec_distance((int *)(obj + 0x18), (int *)(iVar3 + 0x18));
            fVar1 = (float)(dVar5 * (double)lbl_803E5AF8);
        } else {
            dVar7 = (double)(lbl_803E5B48 *
                             (float)((double)CONCAT44(0x43300000,
                                                       *(uint *)((int)&lbl_803AD088 + 0x1c) ^ 0x80000000) -
                                     lbl_803E5B00) +
                             lbl_803E5B48 * *(float *)((int)&lbl_803AD088 + 0xc));
            dVar6 = (double)(lbl_803E5B48 *
                             (float)((double)CONCAT44(0x43300000,
                                                       *(uint *)(state + 0x44) ^ 0x80000000) -
                                     lbl_803E5B00) +
                             lbl_803E5B48 * *(float *)(state + 0x34));
            fVar1 = (float)(dVar7 - dVar6);
            if (fVar1 < lbl_803E5AE8) {
                fVar1 = -fVar1;
            }
        }
        fVar2 = *(float *)(state + 0x1c);
        if (fVar2 < fVar1) {
            if (fVar1 < *(float *)(state + 0x18)) {
                dVar5 = (double)(((fVar1 - fVar2) / (*(float *)(state + 0x18) - fVar2)) *
                                 (*(float *)(state + 0x20) - *(float *)(state + 0x24)) +
                                 *(float *)(state + 0x24));
            } else {
                dVar5 = (double)*(float *)(state + 0x20);
            }
        } else {
            dVar5 = (double)*(float *)(state + 0x24);
        }
        if (*(char *)(state + 0x434) == '\0') {
            fVar1 = (float)(dVar6 - dVar7);
            if (fVar1 < lbl_803E5AE8) {
                fVar1 = -fVar1;
            }
            if (lbl_803DC0E0 < fVar1) {
                dVar5 = (double)lbl_803E5AE8;
            }
        }
    } else {
        iVar3 = (**(code **)(*gCheckpointInterface + 0x34))(state + 0x28);
        if (iVar3 == 2) {
            dVar5 = (double)lbl_803E5B60;
        } else {
            dVar5 = (double)lbl_803E5B64;
        }
    }
    return dVar5;
}
