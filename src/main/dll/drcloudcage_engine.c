#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_channel_query_api.h"
#include "main/audio/sfx_channel_volume_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/game_object.h"
#include "main/objfx.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/dll/DR/DRcloudcage.h"
#include "main/dll/DR/drcloudcage_internal.h"

f32 gDrCloudCageWindVolume;

extern f32 lbl_803E5AE8;
extern f32 lbl_803E5AEC;
extern f32 lbl_803E5AF8;
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

typedef struct DRCloudCagePulseParams
{
    u8 pad[8];
    f32 unk8;
    f32 unkC;
    f32 unk10;
    f32 unk14;
} DRCloudCagePulseParams;

void drcloudcage_updateEngineFx(GameObject* obj, void* state, f32 distanceScale, int intensity, u8* unused,
                                u8 channelFlags)
{
    f32 clamped;
    f32 windVol;
    f32 fv;
    int vol;
    f32 channelVol;
    DRCloudCagePulseParams pulse;

    clamped =
        (distanceScale < lbl_803E5AE8) ? lbl_803E5AE8 : ((distanceScale > lbl_803E5B08) ? lbl_803E5B08 : distanceScale);
    if (channelFlags & 1)
    {
        if (Sfx_IsPlayingFromObjectChannel((int)obj, 8))
        {
            gDrCloudCageWindVolume = lbl_803E5B0C * clamped;
            if (gDrCloudCageWindVolume < lbl_803E5AE8)
            {
                gDrCloudCageWindVolume = -gDrCloudCageWindVolume;
            }
            if (gDrCloudCageWindVolume < *(f32*)&lbl_803E5B10)
            {
                gDrCloudCageWindVolume = lbl_803E5B10;
            }
            if (gDrCloudCageWindVolume > *(f32*)&lbl_803E5B14)
            {
                gDrCloudCageWindVolume = lbl_803E5B14;
            }
            if (((DRCloudCageState*)state)->distanceGate < lbl_803E5B18)
            {
                vol = (int)(lbl_803E5B1C * clamped);
                if (vol < 0)
                {
                    vol = -vol;
                }
                if (vol > 0x7f)
                {
                    vol = 0x7f;
                }
            }
            else
            {
                vol = 0;
            }
            Sfx_SetObjectChannelVolume((u32)obj, 8, vol & 0xff,
                                       lbl_803E5B20 + gDrCloudCageWindVolume / lbl_803E5B08);
        }
    }
    if (channelFlags & 2)
    {
        if (Sfx_IsPlayingFromObjectChannel((int)obj, 1))
        {
            if (((DRCloudCageState*)state)->distanceGate < lbl_803E5B18)
            {
                windVol = 0.0f;
                if (windVol != clamped)
                {
                    windVol = clamped * (f32)obj->anim.rotZ / lbl_803E5B24;
                }
                gDrCloudCageWindVolume = windVol;
                fv = (f32)(f64)windVol;
                if (fv < 0.0f)
                {
                    gDrCloudCageWindVolume = -fv;
                }
                else if (fv > lbl_803E5AEC)
                {
                    gDrCloudCageWindVolume = lbl_803E5AEC;
                }
                vol = (int)(lbl_803E5B28 * gDrCloudCageWindVolume);
                if ((f32)vol > lbl_803E5B28)
                {
                    vol = 0x7f;
                }
                else if ((f32)vol < 0.0f)
                {
                    vol = 0;
                }
                Sfx_SetObjectChannelVolume((u32)obj, 1, vol & 0xff, lbl_803E5B20 + gDrCloudCageWindVolume);
            }
        }
    }
    if (channelFlags & 4)
    {
        Sfx_PlayFromObject((u32)obj, ((DRCloudCageState*)state)->windSfxId);
        Sfx_PlayFromObject((u32)obj, SFXTRIG_tr_gal_rumblelp11);
        if (intensity > 5)
        {
            ((DRCloudCageState*)state)->channel2Vol = ((DRCloudCageState*)state)->channel2Vol + timeDelta;
        }
        else
        {
            if (((DRCloudCageState*)state)->channel2Vol > lbl_803E5B10)
            {
                ((DRCloudCageState*)state)->channel2Vol =
                    -(lbl_803E5B2C * timeDelta - ((DRCloudCageState*)state)->channel2Vol);
            }
        }
        if (((DRCloudCageState*)state)->channel2Vol > *(f32*)&lbl_803E5B08)
        {
            ((DRCloudCageState*)state)->channel2Vol = lbl_803E5B08;
        }
        if (((DRCloudCageState*)state)->channel2Vol < *(f32*)&lbl_803E5B30)
        {
            ((DRCloudCageState*)state)->channel2Vol = lbl_803E5B30;
        }
        channelVol = ((DRCloudCageState*)state)->channel2Vol;
        ((void (*)(GameObject*, u32, u8, f32))Sfx_SetObjectChannelVolume)(obj, 2, channelVol, channelVol * lbl_803E5B38 + lbl_803E5B34);
        if (intensity > 5)
        {
            ((DRCloudCageState*)state)->channel4Vol = lbl_803E5B3C + intensity;
        }
        else
        {
            if (((DRCloudCageState*)state)->channel4Vol > lbl_803E5B3C)
            {
                ((DRCloudCageState*)state)->channel4Vol =
                    -(lbl_803E5AF8 * timeDelta - ((DRCloudCageState*)state)->channel4Vol);
            }
        }
        if (((DRCloudCageState*)state)->channel4Vol > *(f32*)&lbl_803E5B40)
        {
            ((DRCloudCageState*)state)->channel4Vol = lbl_803E5B40;
        }
        if (((DRCloudCageState*)state)->channel4Vol < *(f32*)&lbl_803E5B44)
        {
            ((DRCloudCageState*)state)->channel4Vol = lbl_803E5B44;
        }
        channelVol = ((DRCloudCageState*)state)->channel4Vol;
        ((void (*)(GameObject*, u32, u8, f32))Sfx_SetObjectChannelVolume)(obj, 4, channelVol, channelVol / lbl_803E5B48);
        pulse.unkC = lbl_803E5B4C;
        pulse.unk10 = lbl_803E5B50;
        pulse.unk14 = lbl_803E5B54;
        pulse.unk8 = lbl_803E5AE8;
        objfx_spawnLightPulse(obj, lbl_803E5AF8, 2, 0, 1, ((DRCloudCageState*)state)->channel4Vol / lbl_803E5B58,
                              &pulse);
        pulse.unkC = lbl_803E5B5C;
        objfx_spawnLightPulse(obj, lbl_803E5AF8, 2, 0, 1, ((DRCloudCageState*)state)->channel4Vol / lbl_803E5B58,
                              &pulse);
    }
    fn_801E9C00(obj, (int)state);
}
