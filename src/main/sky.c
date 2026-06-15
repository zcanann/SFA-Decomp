#include "main/sky_state.h"
#include "main/sky_80080E58_shared.h"

int getEnvFxBit2BA(void)
{
    return (u8)GameBit_Get(0x2ba);
}

void setGameBit2BA(int value)
{
    if ((u8)value >= 0x1c)
    {
        value = 0;
    }
    GameBit_Set(0x2ba, (u8)value);
}

void envFxFn_800887cc(void)
{
    playerEnvFxFn_80088ad4((u8)GameBit_Get(0x2ba));
}

void envFxActFn_800887f8(u8 value)
{
    void* player;
    int masked;

    lbl_803DD140 = value;
    masked = (u8)value;
    masked &= 8;
    if (masked == 0)
    {
        player = Obj_GetPlayerObject();
        getEnvfxAct(player, player, 0x136, 0);
        getEnvfxAct(player, player, 0x137, 0);
        getEnvfxAct(player, player, 0x143, 0);
    }
}

void fn_80088870(int a, int b, int c, int d)
{
    lbl_803DD13C = a;
    lbl_803DD130 = b;
    lbl_803DD138 = c;
    lbl_803DD134 = d;
}

void envFxFn_80088884(void)
{
    u8 a;
    u8 b;
    u8 flags;

    a = (u8)(*gSkyInterface)->getSunPosition(0);
    b = (u8)GameBit_Get(0x2ba);
    if (a != lbl_803DD16C)
    {
        lbl_803DD16C = a;
        if (a == 0)
        {
            b++;
            if (b == 0x1c)
            {
                b = 0;
            }
            GameBit_Set(0x2ba, b);
        }
        if (lbl_803DD140 != 0)
        {
            lbl_803DD140 |= 0x10;
        }
    }
    flags = lbl_803DD140;
    if ((flags & 0x10) == 0)
    {
        return;
    }
    flags = (u8)(flags & ~0x10);
    lbl_803DD140 = flags;
    if ((u32)lbl_803DD130 != 0 && (flags & 0x2) != 0 && GameBit_Get(0x3ac) == 0)
    {
        if ((lbl_803DD140 & 0x20) != 0)
        {
            getEnvfxActImmediately(0, 0, (u16)((s16*)lbl_803DD130)[b], 0);
        }
        else
        {
            getEnvfxAct(0, 0, (u16)((s16*)lbl_803DD130)[b], 0);
        }
    }
    if ((u32)lbl_803DD13C != 0 && (lbl_803DD140 & 0x4) != 0)
    {
        if ((lbl_803DD140 & 0x20) != 0)
        {
            getEnvfxActImmediately(0, 0, (u16)((s16*)lbl_803DD13C)[b], 0);
        }
        else
        {
            getEnvfxAct(0, 0, (u16)((s16*)lbl_803DD13C)[b], 0);
        }
    }
    if ((u32)lbl_803DD138 != 0 && (lbl_803DD140 & 0x1) != 0 && GameBit_Get(0x3ab) == 0)
    {
        if ((lbl_803DD140 & 0x20) != 0)
        {
            getEnvfxActImmediately(0, 0, (u16)((s16*)lbl_803DD138)[b], 0);
        }
        else
        {
            getEnvfxAct(0, 0, (u16)((s16*)lbl_803DD138)[b], 0);
        }
    }
    playerEnvFxFn_80088ad4(b);
    lbl_803DD140 &= ~0x20;
}

void loadSunAndMoon(void)
{
    void* moonObj;

    if (lbl_803DD154 == 0)
    {
        gSkySunObject = Obj_SetupObject(Obj_AllocObjectSetup(0x20, 0x62b), 4, -1, -1, NULL);
        moonObj = Obj_SetupObject(Obj_AllocObjectSetup(0x20, 0x62c), 4, -1, -1, NULL);
        gSkyMoonObject = moonObj;
        lbl_803DD154 = 1;
        ObjModel_SetRenderCallback(Obj_GetActiveModel(moonObj), moonFxCb_80074110);
    }
}

int getSkyColorFn_80088e08(int slot)
{
    u8* sky;

    sky = lbl_803DD12C;
    if (sky != NULL)
    {
        return ((SkyBlendStateFlags*)(sky + slot * 0xa4 + 0xc1))->unused80;
    }
    return 0;
}

int getSkyColorFn_80088e30(int slot)
{
    u8* sky;

    sky = lbl_803DD12C;
    if (sky != NULL)
    {
        return sky[slot * 0xa4 + 0xc0];
    }
    return 0xff;
}

int getSkyStructField24C(void)
{
    u8* sky;

    sky = lbl_803DD12C;
    if (sky != NULL)
    {
        return ((SkyState*)sky)->currentLightIndex;
    }
    return 0;
}

void skyGetCurrentTextureColor(u8* red, u8* green, u8* blue)
{
    u8* color;

    if (lbl_803DD12C != NULL)
    {
        *red = gSkyCurrentTextureColor;
        color = &gSkyCurrentTextureColor;
        *green = color[1];
        *blue = color[2];
        return;
    }
    *red = 0xff;
    *green = 0xff;
    *blue = 0xff;
}

void skyGetCurrentAmbientAndLightColors(u8* ambientRed, u8* ambientGreen, u8* ambientBlue, u8* lightRed,
                                        u8* lightGreen, u8* lightBlue)
{
    u8* color;
    u8 red;
    u8 green;
    u8 blue;

    if (gSkyOverrideLightColorEnabled != 0)
    {
        red = gSkyOverrideLightColor;
        *ambientRed = red;
        *lightRed = red;
        color = &gSkyOverrideLightColor;
        green = color[1];
        *ambientGreen = green;
        *lightGreen = green;
        blue = color[2];
        *ambientBlue = blue;
        *lightBlue = blue;
        return;
    }

    if (lbl_803DD12C != NULL)
    {
        *ambientRed = gSkyCurrentAmbientColor;
        color = &gSkyCurrentAmbientColor;
        *ambientGreen = color[1];
        *ambientBlue = color[2];
        *lightRed = gSkyCurrentLightColor;
        color = &gSkyCurrentLightColor;
        *lightGreen = color[1];
        *lightBlue = color[2];
        return;
    }

    *ambientRed = 0xff;
    *ambientGreen = 0xff;
    *ambientBlue = 0xff;
    *lightRed = 0xff;
    *lightGreen = 0xff;
    *lightBlue = 0xff;
}

void* fn_8008912C(void)
{
    return lbl_803DD150;
}

void skyBuildSunModelMatrix(f32 mtx[3][4])
{
    f32 scale;
    f32 scaleMtx[3][4];

    scale = EXIInputFlag / *(f32*)(gSkySunObject + 8);
    PSMTXScale(scaleMtx, scale, scale, scale);
    Obj_BuildWorldTransformMatrix(gSkySunObject, mtx, 0);
    PSMTXConcat(mtx, scaleMtx, mtx);
}

int skyFn_8008919c(int slot)
{
    u8* sky;

    sky = lbl_803DD12C;
    if (sky == NULL)
    {
        return 0;
    }

    if (((SkyBlendStateFlags*)(sky + slot * 0xa4 + 0xc1))->unused80 != 0)
    {
        return 0;
    }
    return gSkySunObject[0x37];
}

void skySetOverrideLightColor(u8 red, u8 green, u8 blue)
{
    u8* color;

    gSkyOverrideLightColor = red;
    color = &gSkyOverrideLightColor;
    color[1] = green;
    color[2] = blue;
}

void skySetOverrideLightColorEnabled(u8 enabled)
{
    gSkyOverrideLightColorEnabled = enabled;
}

void skySetOverrideLightDirection(f32 x, f32 y, f32 z, f32 intensity)
{
    gSkyOverrideLightDirection[0] = x;
    gSkyOverrideLightDirection[1] = y;
    gSkyOverrideLightDirection[2] = z;
    gSkyOverrideLightIntensity = intensity;
    PSVECNormalize(gSkyOverrideLightDirection, gSkyOverrideLightDirection);
}

void skySetOverrideLightDirectionEnabled(u8 enabled)
{
    gSkyOverrideLightDirectionEnabled = enabled;
}

void skyFn_800894a8(int flags, f32 x, f32 y, f32 z)
{
    int bit;

    if (lbl_803DD12C == NULL)
    {
        return;
    }
    for (bit = 0; bit < 2; bit++)
    {
        if ((flags & (1 << bit)) != 0)
        {
            *(f32*)(lbl_803DD12C + bit * 0xa4 + 0xa8) = x;
            *(f32*)(lbl_803DD12C + bit * 0xa4 + 0xac) = y;
            *(f32*)(lbl_803DD12C + bit * 0xa4 + 0xb0) = z;
        }
    }
}

void fn_80089510(int flags, u8 red, u8 green, u8 blue)
{
    int bit;

    if (lbl_803DD12C == NULL)
    {
        return;
    }
    for (bit = 0; bit < 2; bit++)
    {
        if ((flags & (1 << bit)) != 0)
        {
            lbl_803DD12C[bit * 0xa4 + 0x8c] = red;
            lbl_803DD12C[bit * 0xa4 + 0x8d] = green;
            lbl_803DD12C[bit * 0xa4 + 0x8e] = blue;
        }
    }
}

void fn_80089578(int flags, u8 red, u8 green, u8 blue)
{
    int bit;

    if (lbl_803DD12C == NULL)
    {
        return;
    }
    for (bit = 0; bit < 2; bit++)
    {
        if ((flags & (1 << bit)) != 0)
        {
            lbl_803DD12C[bit * 0xa4 + 0x84] = red;
            lbl_803DD12C[bit * 0xa4 + 0x85] = green;
            lbl_803DD12C[bit * 0xa4 + 0x86] = blue;
        }
    }
}

void skyFn_800895e0(int flags, u8 red, u8 green, u8 blue, u8 m1, u8 m2)
{
    int r1, g1, b1, r2, g2, b2;
    int bit;

    if (lbl_803DD12C == NULL)
    {
        return;
    }
    r1 = red * m1 >> 8;
    g1 = green * m1 >> 8;
    b1 = blue * m1 >> 8;
    r2 = red * m2 >> 8;
    g2 = green * m2 >> 8;
    b2 = blue * m2 >> 8;
    for (bit = 0; bit < 2; bit++)
    {
        if ((flags & (1 << bit)) != 0)
        {
            lbl_803DD12C[bit * 0xa4 + 0x7c] = red;
            lbl_803DD12C[bit * 0xa4 + 0x7d] = green;
            lbl_803DD12C[bit * 0xa4 + 0x7e] = blue;
            lbl_803DD12C[bit * 0xa4 + 0x84] = r1;
            lbl_803DD12C[bit * 0xa4 + 0x85] = g1;
            lbl_803DD12C[bit * 0xa4 + 0x86] = b1;
            lbl_803DD12C[bit * 0xa4 + 0x8c] = r2;
            lbl_803DD12C[bit * 0xa4 + 0x8d] = g2;
            lbl_803DD12C[bit * 0xa4 + 0x8e] = b2;
        }
    }
}

void getTimeOfDay(f32* time)
{
    u8* sky;

    sky = lbl_803DD12C;
    if (sky == NULL)
    {
        *time = pEXIInputFlag;
        return;
    }
    *time = ((SkyState*)sky)->timeOfDay;
}

void renderSky(void)
{
    if (gSkySunObject != NULL && gSkyMoonObject != NULL)
    {
        renderSunAndMoon();
    }
    skyFn_8008a500();
    skyFn_8008a04c();
}

#pragma dont_inline on
void getAmbientColor(int slot, u8* red, u8* green, u8* blue)
{
    u8* sky;
    int offset;

    sky = lbl_803DD12C;
    if (sky == NULL)
    {
        *blue = 0xff;
        *green = 0xff;
        *red = 0xff;
        return;
    }

    offset = slot * 0xa4;
    *red = lbl_803DD12C[offset + 0x78];
    *green = lbl_803DD12C[offset + 0x79];
    *blue = lbl_803DD12C[offset + 0x7a];
}
#pragma dont_inline reset

void textureColorFn_8008991c(int slot, u8* red, u8* green, u8* blue)
{
    u8* sky;
    int offset;

    sky = lbl_803DD12C;
    if (sky == NULL)
    {
        *blue = 0xff;
        *green = 0xff;
        *red = 0xff;
        return;
    }

    offset = slot * 0xa4;
    *red = lbl_803DD12C[offset + 0x88];
    *green = lbl_803DD12C[offset + 0x89];
    *blue = lbl_803DD12C[offset + 0x8a];
}

void modelTextureFn_80089970(int slot)
{
    int offset;
    u8* sky;

    if (lbl_803DD144 != NULL)
    {
        offset = slot * 0xa4;
        sky = lbl_803DD12C + offset;
        modelLightStruct_setDirection(lbl_803DD144, ((SkyState*)sky)->lights[0].directionX,
                                      ((SkyState*)sky)->lights[0].directionY,
                                      ((SkyState*)sky)->lights[0].directionZ);
        modelLightStruct_setDiffuseColor(lbl_803DD144, lbl_803DD12C[offset + 0x78],
                                         lbl_803DD12C[offset + 0x79],
                                         lbl_803DD12C[offset + 0x7a], 0xff);
    }
    if (lbl_803DD168 != NULL)
    {
        offset = slot * 0xa4;
        sky = lbl_803DD12C + offset;
        modelLightStruct_setDirection(lbl_803DD168, ((SkyState*)sky)->lights[0].unk7C,
                                      ((SkyState*)sky)->lights[0].unk80,
                                      ((SkyState*)sky)->lights[0].unk84);
        modelLightStruct_setDiffuseColor(lbl_803DD168, lbl_803DD12C[offset + 0x80],
                                         lbl_803DD12C[offset + 0x81],
                                         lbl_803DD12C[offset + 0x82], 0xff);
    }
    lightSetColor(0, lbl_803DD12C[slot * 0xa4 + 0x88], lbl_803DD12C[slot * 0xa4 + 0x89],
                  lbl_803DD12C[slot * 0xa4 + 0x8a]);
}

void* fn_80089A50(void)
{
    return lbl_803DD168;
}

void* fn_80089A58(void)
{
    return lbl_803DD144;
}

#pragma opt_common_subs off
#pragma dont_inline on
int getSunPos(f32* outTime)
{
    f32 time;

    if (lbl_803DD12C == NULL)
    {
        if (outTime != NULL)
        {
            *outTime = pEXIInputFlag;
        }
        return 0;
    }

    time = ((SkyState*)lbl_803DD12C)->timeOfDay;
    if (time >= lbl_803DF088 || time < lbl_803DF084)
    {
        if (outTime != NULL)
        {
            if (time >= lbl_803DF088)
            {
                *outTime = lbl_803DF084 + (time - lbl_803DF088);
            }
            else
            {
                *outTime = lbl_803DF084 - time;
            }
        }
        return 1;
    }

    if (outTime != NULL)
    {
        *outTime = lbl_803DF088 - time;
    }
    return 0;
}
#pragma dont_inline reset

void fn_8008B88C(int* outTimer)
{
    u8* sky;

    sky = lbl_803DD12C;
    if (sky == NULL)
    {
        *outTimer = 0;
        return;
    }
    *outTimer = ((SkyState*)sky)->unk218;
}

#pragma opt_loop_invariants off
void skyFn_80089710(int flags, u32 enabled, int startComplete)
{
    u8* sky;
    u32 flagBit;
    u32 stateActive;
    u32 requestedActive;

    sky = lbl_803DD12C;
    if (sky == NULL)
    {
        return;
    }

    for (flagBit = 0; flagBit < 2; flagBit++)
    {
        if ((flags & (1 << flagBit)) != 0)
        {
            sky = lbl_803DD12C;
            stateActive = ((SkyBlendStateFlags*)(sky + flagBit * 0xa4 + 0xc1))->active;
            if (stateActive != (u8)enabled)
            {
                if (startComplete != 0)
                {
                    ((SkyState*)sky)->lights[flagBit].unk9C = EXIInputFlag;
                }
                else
                {
                    ((SkyState*)sky)->lights[flagBit].unk9C = pEXIInputFlag;
                }
            }
            sky = lbl_803DD12C;
            ((SkyBlendStateFlags*)(sky + flagBit * 0xa4 + 0xc1))->active = enabled;
        }
    }
}
#pragma opt_loop_invariants reset

void fn_800897D4(int slot, f32* x, f32* y, f32* z)
{
    u8* sky;
    int offset;
    f32 fallback;

    if (lbl_803DD12C == NULL)
    {
        fallback = pEXIInputFlag;
        *x = fallback;
        *y = lbl_803DF06C;
        *z = fallback;
        return;
    }

    offset = slot * 0xa4;
    sky = lbl_803DD12C + offset;
    *x = ((SkyState*)sky)->lights[0].directionX;
    sky = lbl_803DD12C + offset;
    *y = ((SkyState*)sky)->lights[0].directionY;
    sky = lbl_803DD12C;
    sky += offset;
    *z = ((SkyState*)sky)->lights[0].directionZ;
}

void objGetColor(int slot, u8* red, u8* green, u8* blue)
{
    u8* sky;
    int offset;

    sky = lbl_803DD12C;
    if (sky == NULL)
    {
        *blue = 0xff;
        *green = 0xff;
        *red = 0xff;
    }
    else
    {
        offset = slot * 0xa4;
        *red = lbl_803DD12C[offset + 0x78];
        *green = lbl_803DD12C[offset + 0x79];
        *blue = lbl_803DD12C[offset + 0x7a];
    }

    *red = (u8)((*red * colorScale) >> 8);
    *green = (u8)((*green * colorScale) >> 8);
    *blue = (u8)((*blue * colorScale) >> 8);
}

void dll_06_func0B(int* x, int* y)
{
    u8* state;
    f32 value;

    state = lbl_803DD184;
    if (state != NULL)
    {
        value = *(f32*)(state + 0x14);
        *x = value;
        value = *(f32*)(lbl_803DD184 + 0x18);
        *y = value;
    }
}

void dll_06_func0A(int* a, int* b, int* c, f32* scale)
{
    u8* state;

    state = lbl_803DD184;
    if (state == NULL)
    {
        return;
    }
    *a = *(int*)(state + 0x24);
    *b = *(int*)(lbl_803DD184 + 0x28);
    *c = *(int*)(lbl_803DD184 + 0x2c);
    *scale = *(f32*)(lbl_803DD184 + 0x30c);
}

void dll_06_func0E(void)
{
    if (lbl_803DD184 == NULL)
    {
        return;
    }
    if (lbl_803DD180 != 1)
    {
        lbl_803DD180 = 1;
    }
}

void dll_06_func0D(void)
{
    if (lbl_803DD184 == NULL)
    {
        return;
    }
    if (lbl_803DD180 != 2)
    {
        lbl_803DD180 = 2;
    }
}

#pragma opt_propagation off
void sky2_initialise(void)
{
    u8** states;
    u8* state;

    lbl_803DB610 = -1;
    (&lbl_803DB610)[1] = -1;
    if (lbl_803DD184 != NULL)
    {
        mm_free(lbl_803DD184);
    }
    states = &lbl_803DD184;
    state = states[1];
    if (state != NULL)
    {
        mm_free(state);
    }
    lbl_803DD184 = NULL;
    states[1] = NULL;
}
#pragma opt_propagation reset

void fn_8008EDE8(f32* out)
{
    u8* state;

    state = lbl_803DD19C;
    if (state == NULL)
    {
        return;
    }
    out[0] = *(f32*)(state + 0);
    out[1] = *(f32*)(lbl_803DD19C + 4);
    out[2] = *(f32*)(lbl_803DD19C + 8);
}

int fn_8008B71C(int slot)
{
    u8* sky;

    sky = lbl_803DD12C;
    if (sky != NULL)
    {
        return ((SkyBlendStateFlags*)(sky + slot * 0xa4 + 0xc1))->bit20;
    }
    return 0;
}

void skyTimeToDayHourMinute(f32 time, s16* days, s16* hours, s16* minutes)
{
    s32 remaining;

    remaining = (s32)time;
    *days = remaining / 0x34bc0;
    remaining -= *days * 0x34bc0;
    *hours = remaining / 0xe10;
    remaining -= *hours * 0xe10;
    *minutes = remaining / 0x3c;
}

void skyGetClockTime(f32* time)
{
    u8* sky;

    sky = lbl_803DD12C;
    if (sky == NULL)
    {
        *time = pEXIInputFlag;
    }
    else
    {
        *time = ((SkyState*)sky)->clockTime;
    }
}

int dll_06_func0F(void)
{
    u8* state;
    f32 y;

    state = lbl_803DD184;
    if (state == NULL)
    {
        return 0xff;
    }
    y = *(f32*)(state + 0x14);
    if (y < lbl_803DF138)
    {
        return 0;
    }
    if (y > lbl_803DF13C)
    {
        return 0xff;
    }
    return (int)(lbl_803DF118 * ((y - lbl_803DF138) / lbl_803DF140));
}

f32 fn_8008ED88(void)
{
    u8* state;
    u16 totalFrames;
    u16 currentFrame;

    state = lbl_803DD19C;
    if (state != NULL)
    {
        totalFrames = *(u16*)(state + 0x22);
        currentFrame = *(u16*)(state + 0x20);
        return (f32)(s32)(totalFrames - currentFrame) / (f32)totalFrames;
    }
    return lbl_803DF1A0;
}

int return0_80088758(void) { return 0x0; }

void doNothing_800887C4(void)
{
}

void doNothing_800887C8(void)
{
}

int return0_8008B7E8(void) { return 0x0; }

void doNothing_8008B8B0(void)
{
}

void pDll_Sky_setTimeOfDay_nop(void)
{
}

void dll_06_func0C_nop(void)
{
}

int dll_06_func07_ret_0(void) { return 0x0; }

void sky2_release(void)
{
}

void loadLightFn_8008bbc4(void)
{
    u8 done = 0;

    while (getLoadedFileFlags(0) != 0)
    {
        padUpdate();
        checkReset();
        if (done)
        {
            waitNextFrame();
        }
        loadDataFiles();
        dvdCheckError();
        if (done)
        {
            mmFreeTick(0);
            gameTextRun();
            GXFlush_(1, 0);
        }
        if (gDvdErrorPauseActive != 0)
        {
            done = 1;
        }
    }
    gSkyOverrideLightDirectionEnabled = 0;
    gSkyOverrideLightColorEnabled = 0;
    gSkyOverrideLightColor = 0xff;
    (&gSkyOverrideLightColor)[1] = 0xff;
    (&gSkyOverrideLightColor)[2] = 0xff;
    if (lbl_803DD144 == NULL)
    {
        lbl_803DD144 = objCreateLight(0, 1);
        if (lbl_803DD144 != NULL)
        {
            modelLightStruct_setLightKind(lbl_803DD144, 4);
            modelLightStruct_setDirection(lbl_803DD144, pEXIInputFlag, lbl_803DF06C, pEXIInputFlag);
            modelLightStruct_setDiffuseColor(lbl_803DD144, 0xff, 0xff, 0xff, 0xff);
            modelLightStruct_setSpecularColor(lbl_803DD144, 0xff, 0xff, 0xff, 0xff);
        }
        lbl_803DD168 = objCreateLight(0, 1);
        if (lbl_803DD168 != NULL)
        {
            modelLightStruct_setLightKind(lbl_803DD168, 4);
            modelLightStruct_setDirection(lbl_803DD168, pEXIInputFlag, EXIInputFlag, pEXIInputFlag);
            modelLightStruct_setDiffuseColor(lbl_803DD168, 0xff, 0xff, 0xff, 0xff);
            modelLightStruct_setSpecularColor(lbl_803DD168, 0xff, 0xff, 0xff, 0xff);
        }
    }
    fn_8008BDA8();
    skyFn_80088c94(7, 0);
    skyFn_80088e54(0, pEXIInputFlag);
    skyFn_8008a500();
    skyFn_8008a04c();
    lbl_8030F2C8[0] = pEXIInputFlag;
    lbl_8030F2C8[1] = lbl_803DF06C;
    lbl_8030F2C8[2] = pEXIInputFlag;
    lbl_8030F2D4[0] = pEXIInputFlag;
    lbl_8030F2D4[1] = lbl_803DF06C;
    lbl_8030F2D4[2] = pEXIInputFlag;
    lbl_803DD150 = textureLoadAsset(0x5fa);
}

void dll_06_func06(int obj)
{
    u8* s = lbl_803DD184;

    if (s != NULL)
    {
        lbl_803DD180 = 2;
        fn_8005D0BC(obj, (u8) * (int*)(s + 0x24), (u8) * (int*)(s + 0x28),
                    (u8) * (int*)(s + 0x2c), 55);
        s = lbl_803DD184;
        if (*(f32*)(s + 0x14) == *(f32*)(s + 0x18))
        {
            *(f32*)(s + 0x14) = *(f32*)(s + 0x14) - lbl_803DF14C;
        }
        s = lbl_803DD184;
        if (*(f32*)(s + 0x14) > *(f32*)(s + 0x18))
        {
            *(f32*)(s + 0x14) = *(f32*)(s + 0x18) - lbl_803DF14C;
        }
        s = lbl_803DD184;
        fogFn_80070404(*(f32*)(s + 0x14), *(f32*)(s + 0x18));
    }
}

void dll_06_func08(int obj)
{
    u8* s = lbl_803DD184;
    f32 v;
    int alpha;

    if (s != NULL)
    {
        if (lbl_803DB750 == 0 && (*(u16*)(s + 4) & 1) == 0)
        {
            v = *(f32*)(s + 0x14);
            if (v < lbl_803DF108)
            {
                alpha = 255;
            }
            else if (v > lbl_803DF148)
            {
                alpha = 0;
            }
            else
            {
                alpha = (int)(lbl_803DF118 - lbl_803DF118 * (v / lbl_803DF148));
            }
            setTextColor(obj, (u8) * (int*)(s + 0x24), (u8) * (int*)(s + 0x28),
                         (u8) * (int*)(s + 0x2c), (u8)alpha);
        }
        else
        {
            setTextColor(obj, 255, 255, 255, 0);
        }
    }
}

void fn_8008DAE8(int obj)
{
    u8* s;
    f32 v;
    int alpha;

    if (lbl_803DD184 == NULL)
    {
        Obj_SetModelColorOverrideRecursive(obj, 0, 0, 0, 0, 0);
    }
    if (lbl_803DB750 == 0 && (*(u16*)((s = lbl_803DD184) + 4) & 1) == 0)
    {
        v = *(f32*)(s + 0x14);
        if (v < lbl_803DF108)
        {
            alpha = 255;
        }
        else if (v > lbl_803DF148)
        {
            alpha = 0;
        }
        else
        {
            alpha = (int)(lbl_803DF118 - lbl_803DF118 * (v / lbl_803DF148));
        }
        Obj_SetModelColorOverrideRecursive(obj, (u8) * (int*)(s + 0x24),
                                           (u8) * (int*)(s + 0x28),
                                           (u8) * (int*)(s + 0x2c), (u8)alpha, 1);
    }
    else
    {
        Obj_SetModelColorOverrideRecursive(obj, 0, 0, 0, 0, 0);
    }
}

#pragma optimization_level 2
void playerEnvFxFn_80088ad4(u8 idx)
{
    void* player;
    s8 alt;
    int val;

    player = Obj_GetPlayerObject();
    if ((void*)lbl_803DD134 == NULL)
    {
        return;
    }
    if (player == NULL)
    {
        return;
    }
    if ((lbl_803DD140 & 0x8) == 0)
    {
        return;
    }
    if (GameBit_Get(944) != 0)
    {
        return;
    }
    alt = (s8)(idx - 1);
    if (alt < 0)
    {
        alt = 27;
    }
    val = ((s16*)lbl_803DD134)[(u8)idx];
    if (val <= 0 || ((s16*)lbl_803DD134)[(s8)alt] != val)
    {
        getEnvfxAct(player, player, 310, 0);
        getEnvfxAct(player, player, 311, 0);
        getEnvfxAct(player, player, 323, 0);
    }
    val = ((s16*)lbl_803DD134)[(u8)idx];
    if (val > 0)
    {
        if (lbl_803DD140 & 0x20)
        {
            getEnvfxActImmediately(player, player, (u16)val, 0);
        }
        else
        {
            getEnvfxAct(player, player, (u16)val, 0);
        }
    }
}
#pragma optimization_level reset

void dll_06_func09(s32* x, s32* y, s32* z)
{
    Dll06InterpState* state;
    s32 targetX;
    s32 targetY;
    s32 targetZ;
    s32 oldX;
    s32 oldY;
    s32 oldZ;
    f32 blend;

    blend = lbl_803DF108;
    state = (Dll06InterpState*)lbl_803DD184;
    if (state == NULL)
    {
        return;
    }
    if (state != NULL && state->active == 0)
    {
        return;
    }

    oldX = *x;
    oldY = *y;
    oldZ = *z;
    if (state != NULL)
    {
        targetX = state->targetX;
        targetY = state->targetY;
        targetZ = state->targetZ;
        blend = state->blend;
    }

    blend *= lbl_803DF144;
    *x = (s32)((f32)(targetX - oldX) * blend + (f32)oldX);
    *y = (s32)((f32)(targetY - oldY) * blend + (f32)oldY);
    *z = (s32)((f32)(targetZ - oldZ) * blend + (f32)oldZ);
}

void sky2_run(void)
{
    SkyRotQ q;
    f32 vec[3];
    SkyVec3 best;
    f32 height;
    SkyBestIdx idx;
    u8 red;
    u8 green;
    u8 blue;
    s16* cam;
    u8** pp;
    int i;
    u8* p;
    f32* dst;
    int a1;
    int k;
    f32* dirp;
    int off1;
    int off2;
    int d;
    int amp;
    int ri;
    int gi;
    int bi;
    u16 flags;
    f32 r;
    f32 g;
    f32 b;
    f32 sa;
    f32 sb;
    f32 step;
    f32 t;
    f32 u;
    f32 att;
    f32 c158;
    f32 c154;
    f32 c150;
    f32 one;
    f32 z;
    f32 zv;
    f32 spd;
    f32 frzero;
    f32 z2;
    f32 hv;
    f32 diff;
    f32 scale;

    best = *(SkyVec3*)lbl_802C1F98;
    r = lbl_803DF108;
    g = r;
    b = r;
    sa = r;
    sb = r;
    height = r;
    *(u16*)&idx = lbl_803E8460;
    idx.pad = lbl_803E8462;
    getAmbientColor(0, &red, &green, &blue);
    if (lbl_803DB758 != 0)
    {
        z = lbl_803DF108;
        dst = lbl_8039A7B8;
        dst[0] = z;
        dst[1] = z;
        one = lbl_803DF114;
        dst[2] = one;
        c150 = lbl_803DF150;
        dst[3] = c150;
        dst[4] = z;
        c154 = lbl_803DF154;
        dst[5] = c154;
        c158 = lbl_803DF158;
        dst[6] = c158;
        dst[7] = z;
        dst[8] = z;
        dst[9] = c150;
        dst[10] = z;
        dst[11] = c150;
        dst[12] = z;
        dst[13] = z;
        dst[14] = c158;
        dst[15] = c154;
        dst[16] = z;
        dst[17] = c150;
        dst[18] = one;
        dst[19] = z;
        dst[20] = z;
        dst[21] = c154;
        dst[22] = z;
        dst[23] = c154;
        lbl_803DB758 = 0;
    }
    cam = Camera_GetCurrentViewSlot();
    zv = lbl_803DF108;
    vec[0] = zv;
    vec[1] = zv;
    vec[2] = lbl_803DF158;
    q.x = zv;
    q.y = zv;
    q.z = zv;
    q.w = lbl_803DF114;
    *(s16*)&q.rx = -cam[0];
    q.rz = 0;
    q.ry = 0;
    vecRotateZXY(&q, vec);
    i = 0;
    pp = &lbl_803DD184;
    do
    {
        if (*pp != NULL && *(s8*)(*pp + 0x317) != 0)
        {
            lbl_803DB750 = 0;
            p = *pp;
            if (*(int*)(p + 0x48) != 0)
            {
                if ((*(u16*)&((GameObject*)p)->anim.rotZ & 1) == 0)
                {
                    spd = lbl_803DF118;
                    *(f32*)(p + 0x310) = spd * *(f32*)(p + 0x30c);
                    if (*(f32*)(*pp + 0x310) > spd)
                    {
                        *(f32*)(*pp + 0x310) = spd;
                    }
                }
            }
            else if (*(int*)(p + 0x44) != 0)
            {
                *(f32*)(p + 0x30c) = *(f32*)(p + 0x310) / lbl_803DF118;
                p = *pp;
                if ((*(u16*)&((GameObject*)p)->anim.rotZ & 1) == 0)
                {
                    *(f32*)(p + 0x310) =
                        -(timeDelta * *(f32*)(p + 0x58) - *(f32*)(p + 0x310));
                    if (*(f32*)(*pp + 0x310) < (frzero = lbl_803DF108))
                    {
                        *(f32*)(*pp + 0x310) = frzero;
                    }
                }
            }
            if ((*(u16*)(*pp + 4) & 0x100) != 0)
            {
                fn_8008D088(i);
            }
            p = *pp;
            if ((*(u16*)&((GameObject*)p)->anim.rotZ & 0x10) != 0)
            {
                r = *(f32*)(p + 0x70);
                g = ((GameObject*)p)->anim.activeMoveProgress;
                b = *(f32*)&((GameObject*)p)->childObjs[0];
                sa = *(f32*)(p + 0x1fc);
                sb = *(f32*)(p + 0x228);
            }
            else if ((*(u16*)&((GameObject*)p)->anim.flags & 0x20) != 0)
            {
                (*gSkyInterface)->getTimeOfDay(&height);
                t = height / lbl_803DF15C;
                if (t < lbl_803DF108)
                {
                    t = lbl_803DF108;
                }
                if (t > lbl_803DF114)
                {
                    t = lbl_803DF114;
                }
                step = lbl_803DF160;
                if (t <= step)
                {
                    u = t / step;
                    k = 0;
                }
                else if (t <= lbl_803DF144)
                {
                    u = (t - step) / step;
                    k = 1;
                }
                else if (t <= lbl_803DF164)
                {
                    u = (t - lbl_803DF144) / step;
                    k = 2;
                }
                else if (t <= lbl_803DF168)
                {
                    u = (t - lbl_803DF164) / step;
                    k = 3;
                }
                else if (t <= lbl_803DF16C)
                {
                    u = (t - lbl_803DF168) / step;
                    k = 4;
                }
                else if (t <= lbl_803DF170)
                {
                    u = (t - lbl_803DF16C) / step;
                    k = 5;
                }
                else if (t <= lbl_803DF174)
                {
                    u = (t - lbl_803DF170) / step;
                    k = 6;
                }
                else
                {
                    u = (t - lbl_803DF174) / step;
                    k = 7;
                }
                r = Curve_EvalCatmullRom(*pp + (off1 = k * 4) + 0x70, u, 0);
                g = Curve_EvalCatmullRom(*pp + (off2 = (k + 0xb) * 4) + 0x70, u, 0);
                b = Curve_EvalCatmullRom(*pp + (k + 0x16) * 4 + 0x70, u, 0);
                sa = Curve_EvalCatmullRom(*pp + off1 + 0x1fc, u, 0);
                sb = Curve_EvalCatmullRom(*pp + off2 + 0x1fc, u, 0);
            }
            else
            {
                k = 0;
                dirp = lbl_8039A7B8;
                do
                {
                    a1 = (u16)getAngle(dirp[0], dirp[2]);
                    d = a1 - (u16)getAngle(vec[0], vec[2]);
                    if (d < 0)
                    {
                        d *= -1;
                    }
                    if (d > 0x7fff)
                    {
                        d = 0xffff - d;
                    }
                    att = ((lbl_803DF178 - (f32)d) / lbl_803DF178 - lbl_803DF170) /
                        lbl_803DF144;
                    if (att > best.x)
                    {
                        if (best.x > best.y)
                        {
                            best.y = best.x;
                            idx.second = idx.best;
                        }
                        best.x = att;
                        idx.best = k;
                    }
                    else if (att > best.y)
                    {
                        best.y = att;
                        idx.second = k;
                    }
                    dirp += 3;
                    k++;
                }
                while (k < 8);
                z2 = lbl_803DF108;
                if (best.x > z2)
                {
                    p = *pp + idx.best * 4;
                    r = *(f32*)(p + 0x70) * best.x + r;
                    g = ((GameObject*)p)->anim.activeMoveProgress * best.x + g;
                    b = *(f32*)&((GameObject*)p)->childObjs[0] * best.x + b;
                    sa = *(f32*)(*pp + idx.best * 4 + 0x1fc) * best.x + sa;
                    sb = *(f32*)(p + 0x228) * best.x + sb;
                }
                if (best.y > z2)
                {
                    p = *pp + idx.second * 4;
                    r = *(f32*)(p + 0x70) * best.y + r;
                    g = ((GameObject*)p)->anim.activeMoveProgress * best.y + g;
                    b = *(f32*)&((GameObject*)p)->childObjs[0] * best.y + b;
                    sa = *(f32*)(*pp + idx.second * 4 + 0x1fc) * best.y + sa;
                    sb = *(f32*)(p + 0x228) * best.y + sb;
                }
            }
            if (r > lbl_803DF118)
            {
                r = lbl_803DF118;
            }
            else if (r < lbl_803DF108)
            {
                r = lbl_803DF108;
            }
            if (g > lbl_803DF118)
            {
                g = lbl_803DF118;
            }
            else if (g < lbl_803DF108)
            {
                g = lbl_803DF108;
            }
            if (b > lbl_803DF118)
            {
                b = lbl_803DF118;
            }
            else if (b < lbl_803DF108)
            {
                b = lbl_803DF108;
            }
            p = *pp;
            if ((*(u16*)&((GameObject*)p)->anim.flags & 0x40) != 0)
            {
                if (*(s8*)(p + 0x314) == -1)
                {
                    *(u8*)(p + 0x314) = 1;
                    frzero = lbl_803DF108;
                    *(f32*)(*pp + 0x6c) = frzero;
                    diff = sb - sa;
                    *(f32*)(*pp + 0x68) = (f32)randomGetRange(
                        (int)(-diff * lbl_803DF168), (int)(diff * lbl_803DF168));
                    *(f32*)(*pp + 0x64) = lbl_803DF17C * (f32)randomGetRange(1, 10);
                }
                else if (*(s8*)(p + 0x314) == 1)
                {
                    hv = *(f32*)&((GameObject*)p)->anim.jointPoseData;
                    sa = sa + hv;
                    *(f32*)&((GameObject*)p)->anim.jointPoseData = hv + *(f32*)&((GameObject*)p)->anim.modelState;
                    p = *pp;
                    if (*(f32*)&((GameObject*)p)->anim.jointPoseData > *(f32*)&((GameObject*)p)->anim.dll)
                    {
                        *(s8*)(p + 0x314) = (s8)(1 - *(s8*)(p + 0x314));
                    }
                }
                else
                {
                    hv = *(f32*)&((GameObject*)p)->anim.jointPoseData;
                    sa = sa + hv;
                    *(f32*)&((GameObject*)p)->anim.jointPoseData = hv - *(f32*)&((GameObject*)p)->anim.modelState;
                    p = *pp;
                    if (*(f32*)&((GameObject*)p)->anim.jointPoseData < (frzero = lbl_803DF108))
                    {
                        *(s8*)(p + 0x314) = (s8)(1 - *(s8*)(p + 0x314));
                        *(f32*)(*pp + 0x6c) = frzero;
                        amp = (s16)(int)(sb - sa);
                        *(f32*)(*pp + 0x68) = (f32)randomGetRange(-amp / 2, amp / 2);
                        *(f32*)(*pp + 0x64) =
                            lbl_803DF17C * (f32)randomGetRange(1, 10);
                    }
                }
            }
            if (sb > lbl_803DF180)
            {
                sb = lbl_803DF180;
            }
            if (sa > sb)
            {
                sa = sb - lbl_803DF114;
            }
            if (sa <= lbl_803DF108)
            {
                fn_8005CECC(1);
            }
            else
            {
                fn_8005CECC(0);
            }
            p = *pp;
            flags = *(u16*)&((GameObject*)p)->anim.rotZ;
            if ((flags & 8) == 0)
            {
                scale = (f32)(blue + green + red) / lbl_803DF184;
                r *= scale;
                g *= scale;
                b *= scale;
            }
            if ((flags & 1) != 0)
            {
                *(int*)&((GameObject*)p)->anim.velocityX = (int)r;
                *(int*)(*pp + 0x28) = (int)g;
                *(int*)(*pp + 0x2c) = (int)b;
                *(f32*)(*pp + 0x14) = sa;
                *(f32*)(*pp + 0x18) = sb;
                if ((*(u16*)(*pp + 4) & 0x80) == 0)
                {
                    *(int*)(*pp + 0x30) = 0xff;
                    *(int*)(*pp + 0x34) = 0xff;
                    *(int*)(*pp + 0x38) = 0xff;
                    *(f32*)(*pp + 0x1c) = lbl_803DF188;
                    *(f32*)(*pp + 0x20) = lbl_803DF18C;
                }
            }
            else if ((flags & 4) != 0)
            {
                *(int*)&((GameObject*)p)->anim.parent = (int)r;
                *(int*)(*pp + 0x34) = (int)g;
                *(int*)(*pp + 0x38) = (int)b;
                *(f32*)(*pp + 0x1c) = sa;
                *(f32*)(*pp + 0x20) = sb;
                if ((*(u16*)(*pp + 4) & 0x80) == 0)
                {
                    *(int*)(*pp + 0x24) = 0xff;
                    *(int*)(*pp + 0x28) = 0xff;
                    *(int*)(*pp + 0x2c) = 0xff;
                    *(f32*)(*pp + 0x14) = lbl_803DF188;
                    *(f32*)(*pp + 0x18) = lbl_803DF18C;
                }
            }
            else
            {
                ri = (int)r;
                *(int*)&((GameObject*)p)->anim.velocityX = ri;
                gi = (int)g;
                *(int*)(*pp + 0x28) = gi;
                bi = (int)b;
                *(int*)(*pp + 0x2c) = bi;
                *(f32*)(*pp + 0x14) = sa;
                *(f32*)(*pp + 0x18) = sb;
                *(int*)(*pp + 0x30) = ri;
                *(int*)(*pp + 0x34) = gi;
                *(int*)(*pp + 0x38) = bi;
                *(f32*)(*pp + 0x1c) = sa;
                *(f32*)(*pp + 0x20) = sb;
            }
        }
        pp++;
        i++;
    }
    while (i < 2);
}

void sky2_onMapSetup(void)
{
    int i;
    void** slot;
    f32 b;
    f32 a;

    lbl_803DB610 = -1;
    (&lbl_803DB610)[1] = -1;
    i = 0;
    slot = (void**)&lbl_803DD184;
    a = lbl_803DF190;
    b = lbl_803DF194;
    for (; i < 2; i++)
    {
        if (slot[i] == NULL)
        {
            slot[i] = mmAlloc(792, 23, 0);
        }
        memset(slot[i], 0, 792);
        *(int*)((char*)slot[i] + 0x24) = 255;
        *(int*)((char*)slot[i] + 0x28) = 255;
        *(int*)((char*)slot[i] + 0x2c) = 255;
        *(f32*)((char*)slot[i] + 0x14) = a;
        *(f32*)((char*)slot[i] + 0x18) = b;
        *(int*)((char*)slot[i] + 0x30) = 255;
        *(int*)((char*)slot[i] + 0x34) = 255;
        *(int*)((char*)slot[i] + 0x38) = 255;
        *(f32*)((char*)slot[i] + 0x1c) = a;
        *(f32*)((char*)slot[i] + 0x20) = b;
        if (lbl_803DB754 != 0)
        {
            getEnvfxAct(NULL, NULL, 9, 0);
            lbl_803DB754 = 0;
        }
    }
}

#pragma dont_inline on
void skyFn_80088c94(int flags, int mode)
{
    u8* env;
    u8* sky;
    int i;

    for (i = 0; i < 2; i++)
    {
        if ((flags & (1 << i)) != 0)
        {
            if ((u8)mode != 0)
            {
                ((SkyBlendStateFlags*)(lbl_803DD12C + i * 0xa4 + 0xc1))->unused80 = 1;
            }
            else
            {
                ((SkyBlendStateFlags*)(lbl_803DD12C + i * 0xa4 + 0xc1))->unused80 = 0;
            }
        }
    }
    sky = lbl_803DD12C;
    ((SkyBlendStateFlags*)(sky + 0x209))->unused80 =
        ((SkyBlendStateFlags*)(sky + ((SkyState*)sky)->currentLightIndex * 0xa4 + 0xc1))->unused80;
    env = saveGameGetEnvState();
    if (getSaveGameLoadStatus() == 0)
    {
        for (i = 0; i < 2; i++)
        {
            if (((SkyBlendStateFlags*)(lbl_803DD12C + i * 0xa4 + 0xc1))->unused80 != 0)
            {
                env[0x40] |= (2 << i);
            }
            else
            {
                env[0x40] &= ~(2 << i);
            }
        }
    }
}
#pragma dont_inline reset

void skyFn_80088e54(int mode, f32 brightness)
{
    u8* env;
    u8* env2;
    u32 cloudMode;
    int bit;
    f32 unset;
    f32 fullBlend;
    int idx;

    env = saveGameGetEnvState();
    if (((SkyState*)lbl_803DD12C)->currentLightIndex != mode)
    {
        ((SkyState*)lbl_803DD12C)->previousLightIndex = ((SkyState*)lbl_803DD12C)->currentLightIndex;
        ((SkyState*)lbl_803DD12C)->currentLightIndex = (u8)mode;
        unset = pEXIInputFlag;
        if (brightness != unset)
        {
            ((SkyState*)lbl_803DD12C)->unk248 = EXIInputFlag / (lbl_803DF060 * brightness);
            ((SkyState*)lbl_803DD12C)->lightBlendFactor = unset;
        }
        else
        {
            fullBlend = EXIInputFlag;
            ((SkyState*)lbl_803DD12C)->unk248 = fullBlend;
            ((SkyState*)lbl_803DD12C)->lightBlendFactor = fullBlend;
        }
        idx = mode * 0xa4;
        cloudMode = ((SkyBlendStateFlags*)(lbl_803DD12C + idx + 0xc1))->cloud;
        if (cloudMode != 0)
        {
            setDrawCloudsAndLights(cloudMode - 1);
        }
        ((SkyBlendStateFlags*)(lbl_803DD12C + 0x209))->unused80 =
            ((SkyBlendStateFlags*)(lbl_803DD12C + idx + 0xc1))->unused80;
        ((SkyBlendStateFlags*)(lbl_803DD12C + 0x209))->bit20 =
            ((SkyBlendStateFlags*)(lbl_803DD12C + idx + 0xc1))->bit20;
        env2 = saveGameGetEnvState();
        if (getSaveGameLoadStatus() == 0)
        {
            for (bit = 0; bit < 2; bit++)
            {
                if ((u32)((lbl_803DD12C[bit * 0xa4 + 0xc1] >> 7) & 1) != 0)
                {
                    env2[0x40] |= 2 << bit;
                }
                else
                {
                    env2[0x40] &= ~(2 << bit);
                }
            }
        }
        if (mode != 0)
        {
            env[0x40] |= 0x10;
        }
        else
        {
            env[0x40] &= ~0x10;
        }
    }
}

void timeOfDayFn_8008b964(void)
{
    u8* env;
    f32 time;
    int timer;
    int i;
    int count;
    f32 val;
    u8* p;
    int idx;

    time = pEXIInputFlag;
    env = saveGameGetEnvState();
    if (lbl_803DD12C == NULL)
    {
        return;
    }
    if (lbl_803DD154 == 0)
    {
        return;
    }
    else
    {
        {
            ((SkyState*)lbl_803DD12C)->timeOfDay += ((SkyState*)lbl_803DD12C)->timeOfDayRate * timeDelta;
            if (((SkyState*)lbl_803DD12C)->timeOfDay >= lbl_803DF078)
            {
                ((SkyState*)lbl_803DD12C)->timeOfDay = ((SkyState*)lbl_803DD12C)->timeOfDay - lbl_803DF078;
            }
            else if (((SkyState*)lbl_803DD12C)->timeOfDay < pEXIInputFlag)
            {
                ((SkyState*)lbl_803DD12C)->timeOfDay = ((SkyState*)lbl_803DD12C)->timeOfDay + lbl_803DF078;
            }
            if (getSunPos(&time) != 0)
            {
                if (((SkyState*)lbl_803DD12C)->transitionLatch == 0)
                {
                    ((SkyState*)lbl_803DD12C)->transitionLatch = 1;
                }
            }
            else
            {
                if (((SkyState*)lbl_803DD12C)->transitionLatch != 0)
                {
                    timer = ((SkyState*)lbl_803DD12C)->unk218 + 1;
                    ((SkyState*)lbl_803DD12C)->unk218 = timer;
                    if (timer > 0x1e)
                    {
                        ((SkyState*)lbl_803DD12C)->unk218 = 0;
                    }
                    ((SkyState*)lbl_803DD12C)->transitionLatch = 0;
                }
            }
            if (Obj_GetPlayerObject() != NULL)
            {
                *(f32*)env = ((SkyState*)lbl_803DD12C)->timeOfDay;
            }
            i = 0;
            for (count = 2; count != 0; count--)
            {
                p = lbl_803DD12C + i;
                *(f32*)&((GameObject*)p)->extra -= *(f32*)(p + 0xb4) * timeDelta;
                val = *(f32*)(lbl_803DD12C + (idx = i + 0xb8));
                *(f32*)(lbl_803DD12C + idx) =
                    (val < pEXIInputFlag) ? pEXIInputFlag : ((val > EXIInputFlag) ? EXIInputFlag : val);
                *(f32*)(lbl_803DD12C + (idx = i + 0xbc)) -= lbl_803DF0F0 * timeDelta;
                val = *(f32*)(lbl_803DD12C + idx);
                *(f32*)(lbl_803DD12C + idx) =
                    (val < pEXIInputFlag) ? pEXIInputFlag : ((val > EXIInputFlag) ? EXIInputFlag : val);
                i += 0xa4;
            }
            ((SkyState*)lbl_803DD12C)->unk23C -= ((SkyState*)lbl_803DD12C)->unk240 * timeDelta;
            val = ((SkyState*)lbl_803DD12C)->unk23C;
            ((SkyState*)lbl_803DD12C)->unk23C =
                (val < pEXIInputFlag) ? pEXIInputFlag : ((val > EXIInputFlag) ? EXIInputFlag : val);
            ((SkyState*)lbl_803DD12C)->lightBlendFactor += ((SkyState*)lbl_803DD12C)->unk248 * timeDelta;
            val = ((SkyState*)lbl_803DD12C)->lightBlendFactor;
            ((SkyState*)lbl_803DD12C)->lightBlendFactor =
                (val < pEXIInputFlag) ? pEXIInputFlag : ((val > EXIInputFlag) ? EXIInputFlag : val);
        }
    }
}

void fn_8008923C(u8* obj, f32* x, f32* y, f32* z)
{
    u8* lights[4];
    f32 dir[3];
    int count;
    f32 lx;
    f32 ly;
    f32 lz;
    u8** p;
    int i;
    int slot;
    u8 flag;
    f32 mag;
    u8* sk;
    u8* found;
    u8* cur;

    found = NULL;
    cur = NULL;
    if (gSkyOverrideLightDirectionEnabled != 0)
    {
        *x = gSkyOverrideLightDirection[0];
        *y = gSkyOverrideLightDirection[1];
        *z = gSkyOverrideLightDirection[2];
    }
    else
    {
        slot = obj[0xf2];
        if (lbl_803DD12C != NULL)
        {
            flag = ((SkyBlendStateFlags*)(lbl_803DD12C + slot * 0xa4 + 0xc1))->unused80;
        }
        else
        {
            flag = 0;
        }
        if (flag != 0)
        {
            modelLightStruct_selectObjectLights(obj, lights, 4, &count, 2);
            if (count > 0)
            {
                if (*(u8**)&((GameObject*)obj)->anim.modelState != NULL)
                {
                    found = *(u8**)(*(u8**)&((GameObject*)obj)->anim.modelState + 0x3c);
                }
                cur = lights[0];
                if (found != lights[0] && found != NULL)
                {
                    p = &lights[1];
                    for (i = count; i > 1; i--)
                    {
                        if (*p == found)
                        {
                            if (-*(f32*)(cur + 0x130) <
                                lbl_803DF064 * -*(f32*)(found + 0x130))
                            {
                                cur = found;
                            }
                            break;
                        }
                        p++;
                    }
                }
                modelLightStruct_getWorldPosition(cur, &lx, &ly, &lz);
                dir[0] = ((GameObject*)obj)->anim.worldPosX - lx;
                dir[1] = ((GameObject*)obj)->anim.worldPosY - ly;
                dir[2] = ((GameObject*)obj)->anim.worldPosZ - lz;
                mag = PSVECMag(dir);
                if (mag > pEXIInputFlag)
                {
                    PSVECScale(EXIInputFlag / mag, dir, dir);
                    *x = dir[0];
                    *y = dir[1];
                    *z = dir[2];
                }
            }
            else
            {
                cur = NULL;
                dir[0] = lbl_803DF068;
                dir[1] = lbl_803DF06C;
                dir[2] = lbl_803DF068;
                PSVECNormalize(dir, dir);
                *x = dir[0];
                *y = dir[1];
                *z = dir[2];
            }
        }
        else
        {
            if (lbl_803DD12C == NULL)
            {
                *x = pEXIInputFlag;
                *y = lbl_803DF06C;
                *z = pEXIInputFlag;
            }
            else
            {
                slot *= 0xa4;
                sk = lbl_803DD12C + slot;
                *x = *(f32*)(sk + 0x90);
                sk = lbl_803DD12C;
                sk += slot;
                *y = *(f32*)(sk + 0x94);
                sk = lbl_803DD12C;
                sk += slot;
                *z = *(f32*)(sk + 0x98);
            }
        }
    }
    if (*(u8**)&((GameObject*)obj)->anim.modelState != NULL)
    {
        *(u8**)(*(u8**)&((GameObject*)obj)->anim.modelState + 0x3c) = cur;
    }
}

void skyFn_8008a500(void)
{
    f32 dot;
    f32 len;
    f32 time;

    if (lbl_803DD12C != NULL)
    {
        dot = lbl_8030F2C8[2] * lbl_8030F2C8[2] + (lbl_8030F2C8[0] * lbl_8030F2C8[0] +
            lbl_8030F2C8[1] * lbl_8030F2C8[1]);
        if (pEXIInputFlag != dot)
        {
            len = sqrtf(dot);
        }
        else
        {
            len = EXIInputFlag;
        }
        *lbl_8030F2C8 = *lbl_8030F2C8 / len;
        lbl_8030F2C8[1] = lbl_8030F2C8[1] / len;
        lbl_8030F2C8[2] = lbl_8030F2C8[2] / len;
        dot = lbl_8030F2D4[2] * lbl_8030F2D4[2] + (lbl_8030F2D4[0] * lbl_8030F2D4[0] +
            lbl_8030F2D4[1] * lbl_8030F2D4[1]);
        if (pEXIInputFlag != dot)
        {
            len = sqrtf(dot);
        }
        else
        {
            len = EXIInputFlag;
        }
        *lbl_8030F2D4 = *lbl_8030F2D4 / len;
        lbl_8030F2D4[1] = lbl_8030F2D4[1] / len;
        lbl_8030F2D4[2] = lbl_8030F2D4[2] / len;
        time = ((SkyState*)lbl_803DD12C)->timeOfDay;
        if (time >= lbl_803DF084 && time <= lbl_803DF088)
        {
            if (gSkyOverrideLightDirectionEnabled != 0)
            {
                skyFn_80062a54(gSkyOverrideLightDirection[0], gSkyOverrideLightDirection[1],
                               gSkyOverrideLightDirection[2], (int)gSkyOverrideLightIntensity);
            }
            else
            {
                skyFn_80062a54(*lbl_8030F2C8, lbl_8030F2C8[1], lbl_8030F2C8[2], 100);
            }
            (*gCloudActionInterface)->func08Nop(*lbl_8030F2C8, lbl_8030F2C8[1],
                                                lbl_8030F2C8[2], 1);
        }
        else
        {
            if (gSkyOverrideLightDirectionEnabled != 0)
            {
                skyFn_80062a54(gSkyOverrideLightDirection[0], gSkyOverrideLightDirection[1],
                               gSkyOverrideLightDirection[2], (int)gSkyOverrideLightIntensity);
            }
            else
            {
                skyFn_80062a54(-(*lbl_8030F2D4), lbl_8030F2D4[1], -lbl_8030F2D4[2], 100);
            }
            (*gCloudActionInterface)->func08Nop(-(*lbl_8030F2D4), lbl_8030F2D4[1],
                                                -lbl_8030F2D4[2], 0);
        }
    }
}

void sky2_update(int a, int b, u8* cfg)
{
    u8* env;
    u16 bits;
    u8* st;
    int m40;
    u8 flags;
    u8 flags58;
    u8 b1;
    u8 i;

    flags = 0;
    env = saveGameGetEnvState();
    if (cfg != NULL)
    {
        (&lbl_803DB610)[1] = lbl_803DB610 = (s16)((Sky2Config*)cfg)->unk24 - 1;
        *(s16*)(env + 0xc) = (s16)((Sky2Config*)cfg)->unk24 - 1;
        flags58 = ((Sky2Config*)cfg)->unk58;
        b1 = (flags58 & 0x80) ? 1 : 0;
        if (*(s8*)((&lbl_803DD184)[b1] + 0x317) == 0)
        {
            if ((flags58 & 0x40) != 0)
            {
                flags |= 0x40;
            }
            fn_8008C9F4(cfg, flags);
            if ((((Sky2Config*)cfg)->unk58 & 0x40) != 0)
            {
                (&lbl_803DD184)[b1][0x316] = 1;
            }
            *(u16*)((&lbl_803DD184)[b1] + 4) = ((Sky2Config*)cfg)->unk58 | 0x100;
            (&lbl_803DD184)[b1][0x315] = 1;
            *(f32*)((&lbl_803DD184)[b1] + 0x304) = lbl_803DF108;
        }
        else if ((flags58 & 0x20) != 0)
        {
            getEnvfxAct(0, 0, 9, 0);
        }
        else
        {
            *(u16*)((&lbl_803DD184)[b1] + 4) = flags58 | 0x100;
            (&lbl_803DD184)[b1][0x315] = 1;
            *(f32*)((&lbl_803DD184)[b1] + 0x304) = lbl_803DF108;
            for (i = 0; i < 0xb; i++)
            {
                *(f32*)((&lbl_803DD184)[b1] + i * 4 + 0xf4) =
                    (f32)(u32)
                cfg[lbl_8030F4A0[i] + 0xc];
                *(f32*)((&lbl_803DD184)[b1] + i * 4 + 0x120) =
                    (f32)(u32)
                cfg[lbl_8030F4A0[i] + 0x14];
                *(f32*)((&lbl_803DD184)[b1] + i * 4 + 0x14c) =
                    (f32)(u32)
                cfg[lbl_8030F4A0[i] + 0x1c];
                *(f32*)((&lbl_803DD184)[b1] + i * 4 + 0x254) =
                    (f32)(u32) * (u16*)(cfg + lbl_8030F4A0[i] * 2 + 0x3e);
                *(f32*)((&lbl_803DD184)[b1] + i * 4 + 0x280) =
                    (f32)(u32) * (u16*)(cfg + lbl_8030F4A0[i] * 2 + 0x2e);
            }
            *(int*)((&lbl_803DD184)[b1] + 0x3c) = ((Sky2Config*)cfg)->unk2A;
            *(int*)((&lbl_803DD184)[b1] + 0x40) = ((Sky2Config*)cfg)->unk2C;
            *(s8*)((&lbl_803DD184)[b1] + 0x314) = -1;
            if ((((Sky2Config*)cfg)->unk59 & 0x20) != 0)
            {
                st = (&lbl_803DD184)[b1];
                bits = *(u16*)(st + 6);
                if ((bits & 0x20) == 0)
                {
                    *(u16*)(st + 6) = bits | 0x20;
                }
            }
            if ((((Sky2Config*)cfg)->unk59 & 0x20) == 0)
            {
                st = (&lbl_803DD184)[b1];
                bits = *(u16*)(st + 6);
                if ((bits & 0x20) != 0)
                {
                    *(u16*)(st + 6) = bits ^ 0x20;
                }
            }
            if ((((Sky2Config*)cfg)->unk58 & 0x40) != 0)
            {
                *(u16*)((&lbl_803DD184)[b1] + 6) |= 0x40;
                (&lbl_803DD184)[b1][0x316] = 1;
            }
            else
            {
                st = (&lbl_803DD184)[b1];
                bits = *(u16*)(st + 6);
                if ((bits & 0x40) != 0)
                {
                    *(u16*)(st + 6) = bits ^ 0x40;
                }
            }
            m40 = ((Sky2Config*)cfg)->unk59 & 0x40;
            if (m40 != 0)
            {
                st = (&lbl_803DD184)[b1];
                bits = *(u16*)(st + 6);
                if ((bits & 0x40) == 0)
                {
                    *(u16*)(st + 6) = bits | 0x40;
                    return;
                }
            }
            if (m40 == 0)
            {
                st = (&lbl_803DD184)[b1];
                bits = *(u16*)(st + 6);
                if ((bits & 0x40) != 0)
                {
                    *(u16*)(st + 6) = bits ^ 0x40;
                }
            }
        }
    }
}

void fn_8008C9F4(u8* cfg, u8 flags)
{
    int b1;
    int i;
    u8* p2;

    b1 = (((Sky2Config*)cfg)->unk58 & 0x80) ? 1 : 0;
    *(int*)((&lbl_803DD184)[b1]) = 0;
    (&lbl_803DD184)[b1][0x317] = 1;
    for (i = 0; i < 0x21; i++)
    {
        *(f32*)((&lbl_803DD184)[b1] + i * 4 + 0x178) = lbl_803DF108;
    }
    for (i = 0; i < 0x21; i++)
    {
        *(f32*)((&lbl_803DD184)[b1] + i * 4 + 0x70) = lbl_803DF108;
    }
    for (i = 0; i < 0x16; i++)
    {
        *(f32*)((&lbl_803DD184)[b1] + i * 4 + 0x2ac) = lbl_803DF108;
    }
    for (i = 0; i < 0xb; i++)
    {
        *(f32*)((&lbl_803DD184)[b1] + i * 4 + 0x1fc) = lbl_803DF10C;
        *(f32*)((&lbl_803DD184)[b1] + i * 4 + 0x228) = lbl_803DF110;
    }
    p2 = lbl_8030F4A0;
    for (i = 0; i < 0xb; i++)
    {
        *(f32*)((&lbl_803DD184)[b1] + i * 4 + 0xf4) = (f32)(u32)
        cfg[*p2 + 0xc];
        *(f32*)((&lbl_803DD184)[b1] + i * 4 + 0x120) = (f32)(u32)
        cfg[*p2 + 0x14];
        *(f32*)((&lbl_803DD184)[b1] + i * 4 + 0x14c) = (f32)(u32)
        cfg[*p2 + 0x1c];
        *(f32*)((&lbl_803DD184)[b1] + i * 4 + 0x254) = (f32)(u32) * (u16*)(cfg + *p2 * 2 + 0x3e);
        *(f32*)((&lbl_803DD184)[b1] + i * 4 + 0x280) = (f32)(u32) * (u16*)(cfg + *p2 * 2 + 0x2e);
        p2++;
    }
    *(u16*)((&lbl_803DD184)[b1] + 4) = ((Sky2Config*)cfg)->unk58;
    *(u16*)((&lbl_803DD184)[b1] + 6) = ((Sky2Config*)cfg)->unk59;
    *(f32*)((&lbl_803DD184)[b1] + 0x64) = lbl_803DF108;
    *(f32*)((&lbl_803DD184)[b1] + 0x68) = lbl_803DF108;
    *(s8*)((&lbl_803DD184)[b1] + 0x314) = -1;
    *(f32*)((&lbl_803DD184)[b1] + 0x6c) = lbl_803DF108;
    if (((Sky2Config*)cfg)->unk2A == 0)
    {
        ((Sky2Config*)cfg)->unk2A = 1;
    }
    if (((Sky2Config*)cfg)->unk2A != 0)
    {
        *(int*)((&lbl_803DD184)[b1] + 0x3c) = ((Sky2Config*)cfg)->unk2A;
        *(int*)((&lbl_803DD184)[b1] + 0x48) = 1;
        *(int*)((&lbl_803DD184)[b1] + 8) = ((Sky2Config*)cfg)->unk2E;
        *(f32*)((&lbl_803DD184)[b1] + 0x5c) = lbl_803DF114 / (f32)(u32)((Sky2Config*)cfg)->unk2A;
    }
    else
    {
        *(int*)((&lbl_803DD184)[b1] + 0x3c) = 0;
        *(f32*)((&lbl_803DD184)[b1] + 0x5c) = lbl_803DF114;
    }
    if (((Sky2Config*)cfg)->unk2C == 0)
    {
        ((Sky2Config*)cfg)->unk2C = 1;
    }
    if (((Sky2Config*)cfg)->unk2C != 0)
    {
        *(int*)((&lbl_803DD184)[b1] + 0x40) = ((Sky2Config*)cfg)->unk2C;
        *(f32*)((&lbl_803DD184)[b1] + 0x58) =
            lbl_803DF118 / (lbl_803DF11C * ((f32)(u32)((Sky2Config*)cfg)->unk2C / lbl_803DF120));
        *(int*)((&lbl_803DD184)[b1] + 0xc) = 0x5dc;
        *(f32*)((&lbl_803DD184)[b1] + 0x60) = lbl_803DF114 / (f32)(u32)((Sky2Config*)cfg)->unk2C;
    }
    else
    {
        *(int*)((&lbl_803DD184)[b1] + 0x40) = 0;
        *(f32*)((&lbl_803DD184)[b1] + 0x60) = lbl_803DF114;
    }
    *(int*)((&lbl_803DD184)[b1] + 0x44) = 0;
}

#pragma opt_common_subs on
void fn_8008D088(int slot)
{
    SkySlotAnim* p;
    f32 dur;
    f32 zero;
    f32 len;
    f32 spd;
    f32 bv;
    int i;
    u16 flags;
    int flag1;

    p = *(SkySlotAnim**)(&lbl_803DD184 + slot);
    if (p->t >= (dur = lbl_803DF114))
    {
        p->flags4 &= ~0x100;
        zero = lbl_803DF108;
        (*(SkySlotAnim**)(&lbl_803DD184 + slot))->step = zero;
        (*(SkySlotAnim**)(&lbl_803DD184 + slot))->t = zero;
        (*(SkySlotAnim**)(&lbl_803DD184 + slot))->prevT = dur;
        p = *(SkySlotAnim**)(&lbl_803DD184 + slot);
        if (p->b316 != 0 && (p->flags6 & 0x40) == 0)
        {
            p->b316 = 0;
        }
        for (i = 0; i < 0x21; i++)
        {
            (*(SkySlotAnim**)(&lbl_803DD184 + slot))->cur[i] =
                (*(SkySlotAnim**)(&lbl_803DD184 + slot))->target[i];
        }
        for (i = 0; i < 0x16; i++)
        {
            (*(SkySlotAnim**)(&lbl_803DD184 + slot))->cur2[i] =
                (*(SkySlotAnim**)(&lbl_803DD184 + slot))->target2[i];
        }
    }
    else
    {
        if (p->b315 != 0)
        {
            len = lbl_803DF11C * ((f32)p->frameCount / lbl_803DF120);
            if (lbl_803DF108 == len)
            {
                len = dur;
            }
            p->step = *(f32*)&lbl_803DF114 / len;
            for (i = 0; i < 0x21; i++)
            {
                (*(SkySlotAnim**)(&lbl_803DD184 + slot))->vel[i] =
                    ((*(SkySlotAnim**)(&lbl_803DD184 + slot))->target[i] -
                        (*(SkySlotAnim**)(&lbl_803DD184 + slot))->cur[i]) /
                    len;
            }
            for (i = 0; i < 0x16; i++)
            {
                (*(SkySlotAnim**)(&lbl_803DD184 + slot))->vel2[i] =
                    ((*(SkySlotAnim**)(&lbl_803DD184 + slot))->target2[i] -
                        (*(SkySlotAnim**)(&lbl_803DD184 + slot))->cur2[i]) /
                    len;
            }
            (*(SkySlotAnim**)(&lbl_803DD184 + slot))->b315 = 0;
        }
        for (i = 0; i < 0x21; i++)
        {
            (*(SkySlotAnim**)(&lbl_803DD184 + slot))->cur[i] +=
                timeDelta * (*(SkySlotAnim**)(&lbl_803DD184 + slot))->vel[i];
        }
        for (i = 0; i < 0x16; i++)
        {
            (*(SkySlotAnim**)(&lbl_803DD184 + slot))->cur2[i] +=
                timeDelta * (*(SkySlotAnim**)(&lbl_803DD184 + slot))->vel2[i];
        }
        (*(SkySlotAnim**)(&lbl_803DD184 + slot))->t +=
            timeDelta * (*(SkySlotAnim**)(&lbl_803DD184 + slot))->step;
        p = *(SkySlotAnim**)(&lbl_803DD184 + slot);
        flags = p->flags4;
        flag1 = flags & 1;
        if (flag1 != 0 && (bv = p->blend) > (zero = lbl_803DF108))
        {
            p->blend = -(lbl_803DF118 * p->t - bv);
            if ((*(SkySlotAnim**)(&lbl_803DD184 + slot))->blend < zero)
            {
                (*(SkySlotAnim**)(&lbl_803DD184 + slot))->blend = zero;
                lbl_803DB750 = 1;
            }
        }
        else if ((flags & 4) != 0 && p->blend < (spd = lbl_803DF118))
        {
            p->blend = spd * p->t;
            if ((*(SkySlotAnim**)(&lbl_803DD184 + slot))->blend > spd)
            {
                (*(SkySlotAnim**)(&lbl_803DD184 + slot))->blend = spd;
            }
        }
        else if (flag1 == 0 && p->blend < (spd = lbl_803DF118))
        {
            p->blend = spd * p->t;
            if ((*(SkySlotAnim**)(&lbl_803DD184 + slot))->blend > spd)
            {
                (*(SkySlotAnim**)(&lbl_803DD184 + slot))->blend = spd;
            }
        }
        (*(SkySlotAnim**)(&lbl_803DD184 + slot))->prevT =
            (*(SkySlotAnim**)(&lbl_803DD184 + slot))->t;
    }
}
#pragma opt_common_subs reset


void fn_8008BDA8(void)
{
    u8* tex0;
    int iofs;
    int jofs;
    int i;
    int j;

    if (lbl_803DD12C != NULL)
    {
        if (lbl_803DD12C != NULL)
        {
            if (*(u8**)lbl_803DD12C != NULL)
            {
                textureFree(*(u8**)lbl_803DD12C);
            }
            if (((SkyState*)lbl_803DD12C)->handle != NULL)
            {
                textureFree(((SkyState*)lbl_803DD12C)->handle);
            }
            mm_free(((SkyState*)lbl_803DD12C)->unk08);
            mm_free(((SkyState*)lbl_803DD12C)->unk10);
            mm_free(lbl_803DD12C);
        }
        lbl_803DD12C = NULL;
    }
    lbl_803DD12C = mmAlloc(600, 0x17, 0);
    memset(lbl_803DD12C, 0, 600);
    ((SkyState*)lbl_803DD12C)->unk250 = -1;
    ((SkyState*)lbl_803DD12C)->unk218 = randomGetRange(0, 0x1c);
    ((SkyState*)lbl_803DD12C)->unk252 = 0xc;
    ((SkyState*)lbl_803DD12C)->unk253 = 0;
    ((SkyState*)lbl_803DD12C)->timeOfDay = lbl_803DF0F4;
    ((SkyState*)lbl_803DD12C)->clockTime = 0xb4;
    ((SkyState*)lbl_803DD12C)->unk1C = lbl_803DF0F8;
    ((SkyState*)lbl_803DD12C)->timeOfDayRate = (f32)((SkyState*)lbl_803DD12C)->clockTime / lbl_803DF060;
    ((SkyState*)lbl_803DD12C)->skyTextureIds[0] = 0xc38;
    ((SkyState*)lbl_803DD12C)->skyTextureIds[1] = 0xc38;
    ((SkyState*)lbl_803DD12C)->skyTextureIds[2] = 0xc38;
    ((SkyState*)lbl_803DD12C)->skyTextureIds[3] = 0xc38;
    ((SkyState*)lbl_803DD12C)->skyTextureIds[4] = 0xc38;
    ((SkyState*)lbl_803DD12C)->skyTextureIds[5] = 0xc38;
    ((SkyState*)lbl_803DD12C)->skyTextureIds[6] = 0xc38;
    ((SkyState*)lbl_803DD12C)->skyTextureIds[7] = 0xc38;
    *(u8**)lbl_803DD12C = textureLoadAsset(((SkyState*)lbl_803DD12C)->skyTextureIds[0]);
    ((SkyState*)lbl_803DD12C)->handle = textureLoadAsset(((SkyState*)lbl_803DD12C)->skyTextureIds[1]);
    ((SkyState*)lbl_803DD12C)->unk14 = 0xc38;
    ((SkyState*)lbl_803DD12C)->unk18 = 0xc38;
    tex0 = *(u8**)lbl_803DD12C;
    ((SkyState*)lbl_803DD12C)->unk08 = textureAlloc(*(u16*)(tex0 + 0xa), *(u16*)(tex0 + 0xc), 6, 0, 0, 1, 0, 1, 1);
    ((SkyState*)lbl_803DD12C)->unk10 = textureAlloc(*(u16*)(tex0 + 0xa), *(u16*)(tex0 + 0xc), 6, 0, 0, 1, 0, 1, 1);
    iofs = 0;
    i = 0;
    do
    {
        jofs = 0;
        for (j = 0; j < 3; j++)
        {
            *(f32*)((int)lbl_803DD12C + iofs + jofs + 0x20) = lbl_803DF0FC;
            *(f32*)((int)lbl_803DD12C + iofs + jofs + 0x24) = lbl_803DF0FC;
            *(f32*)((int)lbl_803DD12C + iofs + jofs + 0x28) = lbl_803DF0FC;
            *(f32*)((int)lbl_803DD12C + iofs + jofs + 0x2c) = lbl_803DF0FC;
            *(f32*)((int)lbl_803DD12C + iofs + jofs + 0x30) = lbl_803DF0FC;
            *(f32*)((int)lbl_803DD12C + iofs + jofs + 0x34) = lbl_803DF0FC;
            *(f32*)((int)lbl_803DD12C + iofs + jofs + 0x38) = lbl_803DF0FC;
            jofs += 0x1c;
        }
        lbl_803DD12C[iofs + 0x74] = 0xff;
        lbl_803DD12C[iofs + 0x75] = 0xff;
        lbl_803DD12C[iofs + 0x76] = 0xff;
        lbl_803DD12C[iofs + 0x78] = 0xff;
        lbl_803DD12C[iofs + 0x79] = 0xff;
        lbl_803DD12C[iofs + 0x7a] = 0xff;
        lbl_803DD12C[iofs + 0x80] = 0xff;
        lbl_803DD12C[iofs + 0x81] = 0xff;
        lbl_803DD12C[iofs + 0x82] = 0xff;
        lbl_803DD12C[iofs + 0x88] = 0xff;
        lbl_803DD12C[iofs + 0x89] = 0xff;
        lbl_803DD12C[iofs + 0x8a] = 0xff;
        *(f32*)(lbl_803DD12C + iofs + 0x90) = pEXIInputFlag;
        *(f32*)(lbl_803DD12C + iofs + 0x94) = lbl_803DF06C;
        *(f32*)(lbl_803DD12C + iofs + 0x98) = pEXIInputFlag;
        *(f32*)(lbl_803DD12C + iofs + 0x9c) = pEXIInputFlag;
        *(f32*)(lbl_803DD12C + iofs + 0xa0) = lbl_803DF06C;
        *(f32*)(lbl_803DD12C + iofs + 0xa4) = pEXIInputFlag;
        ((SkyBlendStateFlags*)(lbl_803DD12C + iofs + 0xc1))->active = 0;
        *(f32*)(lbl_803DD12C + iofs + 0xa8) = lbl_803DF100;
        *(f32*)(lbl_803DD12C + iofs + 0xac) = EXIInputFlag;
        *(f32*)(lbl_803DD12C + iofs + 0xb0) = lbl_803DF100;
        lbl_803DD12C[iofs + 0x7c] = 0xff;
        lbl_803DD12C[iofs + 0x7d] = 0xff;
        lbl_803DD12C[iofs + 0x7e] = 0xff;
        lbl_803DD12C[iofs + 0x84] = 0xff;
        lbl_803DD12C[iofs + 0x85] = 0xff;
        lbl_803DD12C[iofs + 0x86] = 0xff;
        lbl_803DD12C[iofs + 0x8c] = 0xff;
        lbl_803DD12C[iofs + 0x8d] = 0xff;
        lbl_803DD12C[iofs + 0x8e] = 0xff;
        lbl_803DD12C[iofs + 0xc0] = 0x80;
        iofs += 0xa4;
        i++;
    }
    while (i < 3);
}

void skyFn_8008a04c(void)
{
    int cC;
    int cB;
    int cA;
    f32* vec;
    int iofs;
    f32* pA;
    f32* pB;
    f32* pC;
    int idx7;
    int idx14;
    u8* color;
    int part4;
    int i;
    int t2;
    int blue;
    int c1;
    int part;
    int red;
    int green;
    f32 t;
    f32 tc;
    f32 blend;
    f32 time2;
    u8* p;
    f32 zero;
    f32 frac;
    f32 dayStart;

    vec = lbl_8030F2C8;
    if (lbl_803DD12C == NULL)
    {
        for (blue = 0; blue < 3; blue++)
        {
            fn_80089A60(blue, vec[0], vec[1], vec[2], 0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
        }
    }
    else
    {
        t = ((SkyState*)lbl_803DD12C)->timeOfDay / lbl_803DF078;
        tc = (t < pEXIInputFlag) ? pEXIInputFlag : ((t > EXIInputFlag) ? EXIInputFlag : t);
        if (tc <= lbl_803DF07C)
        {
            frac = tc / lbl_803DF07C;
            part = 0;
        }
        else if (tc <= lbl_803DF068)
        {
            frac = (tc - lbl_803DF07C) / lbl_803DF07C;
            part = 1;
        }
        else if (tc <= init_803DF080)
        {
            frac = (tc - lbl_803DF068) / lbl_803DF07C;
            part = 2;
        }
        else
        {
            frac = (tc - init_803DF080) / lbl_803DF07C;
            part = 3;
        }
        iofs = i = 0;
        part4 = part * 4;
        pA = (f32*)&((u8*)vec)[part4 + 0x40];
        pB = (f32*)&((u8*)vec)[part4 + 0x18];
        pC = (f32*)&((u8*)vec)[part4 + 0x2c];
        idx7 = (part + 7) * 4;
        idx14 = (part + 0xe) * 4;
        color = &gSkyCurrentTextureColor;
        zero = pEXIInputFlag;
        dayStart = lbl_803DF084;
        do
        {
            if ((u32)((lbl_803DD12C[iofs + 0xc1] >> 7) & 1) != 0)
            {
                cA = 0xc8;
                cB = 0;
                cC = 0x60;
            }
            else
            {
                cA = (u8)Curve_EvalLinear(pA, frac, 0);
                cB = (int)Curve_EvalLinear(pB, frac, 0);
                cC = (int)Curve_EvalLinear(pC, frac, 0);
            }
            c1 = (int)Curve_EvalCatmullRom(lbl_803DD12C + iofs + part4 + 0x20, frac, 0);
            t2 = (int)Curve_EvalCatmullRom(lbl_803DD12C + iofs + idx7 + 0x20, frac, 0);
            blue = (int)Curve_EvalCatmullRom(lbl_803DD12C + iofs + idx14 + 0x20, frac, 0);
            p = lbl_803DD12C + iofs;
            blend = *(f32*)&((GameObject*)p)->extra;
            if (blend != zero)
            {
                c1 = (int)(blend * ((f32)p[0x74] - (f32)c1) + (f32)c1);
                t2 = (int)(blend * ((f32)p[0x75] - (f32)t2) + (f32)t2);
                blue = (int)(blend * ((f32)p[0x76] - (f32)blue) + (f32)blue);
            }
            if (c1 < 0)
            {
                red = 0;
            }
            else if (c1 > 0xff)
            {
                red = 0xff;
            }
            else
            {
                red = c1;
            }
            if (t2 < 0)
            {
                green = 0;
            }
            else if (t2 > 0xff)
            {
                green = 0xff;
            }
            else
            {
                green = t2;
            }
            if (blue < 0)
            {
                blue = 0;
            }
            else if (blue > 0xff)
            {
                blue = 0xff;
            }
            if (i == 0)
            {
                gSkyCurrentTextureColor = (u8)red;
                color[1] = (u8)green;
                color[2] = (u8)blue;
            }
            time2 = ((SkyState*)lbl_803DD12C)->timeOfDay;
            if (time2 >= dayStart && time2 <= lbl_803DF088)
            {
                fn_80089A60(i, vec[0], vec[1], vec[2], red, green, blue, cB, cC, cA);
            }
            else
            {
                fn_80089A60(i, -vec[3], vec[4], -vec[5], red, green, blue, cB, cC, cA);
            }
            iofs += 0xa4;
            i++;
        }
        while (i < 2);
        fn_80089A60(2, pEXIInputFlag, pEXIInputFlag, pEXIInputFlag, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff);
    }
}

void fn_80089A60(int slot, f32 x, f32 y, f32 z, int r, int g, int b, int a2, int b2, int c2)
{
    f32 dir[3];
    int c01;
    int c02;
    int c03;
    int c11;
    int c12;
    int c13;
    int pb;
    int cb;
    int ofs;
    u8* p3;
    f32 bl;
    int scale1;
    int scale2;
    u8* prev;
    u8* cur2;

    dir[0] = -x;
    dir[1] = -y;
    dir[2] = -z;
    if (slot == 2)
    {
        prev = lbl_803DD12C + ((SkyState*)lbl_803DD12C)->previousLightIndex * 0xa4 + 0x20;
        cur2 = lbl_803DD12C + ((SkyState*)lbl_803DD12C)->currentLightIndex * 0xa4 + 0x20;
        dir[0] = *(f32*)(prev + 0x70) + ((SkyState*)lbl_803DD12C)->lightBlendFactor *
            (*(f32*)(cur2 + 0x70) - *(f32*)(prev + 0x70));
        dir[1] = *(f32*)(prev + 0x74) + ((SkyState*)lbl_803DD12C)->lightBlendFactor *
            (*(f32*)(cur2 + 0x74) - *(f32*)(prev + 0x74));
        dir[2] = *(f32*)(prev + 0x78) + ((SkyState*)lbl_803DD12C)->lightBlendFactor *
            (*(f32*)(cur2 + 0x78) - *(f32*)(prev + 0x78));
        bl = ((SkyState*)lbl_803DD12C)->lightBlendFactor;
        pb = prev[0x58];
        cb = cur2[0x58];
        r = (int)
        (bl * ((f32)(u32)
        cb - (f32)(u32)
        pb
        )
        +(f32)(u32)
        pb
        )
        ;
        pb = prev[0x59];
        cb = cur2[0x59];
        g = (int)
        (bl * ((f32)(u32)
        cb - (f32)(u32)
        pb
        )
        +(f32)(u32)
        pb
        )
        ;
        pb = prev[0x5a];
        cb = cur2[0x5a];
        b = (int)
        (bl * ((f32)(u32)
        cb - (f32)(u32)
        pb
        )
        +(f32)(u32)
        pb
        )
        ;
        pb = prev[0x60];
        cb = cur2[0x60];
        c01 = (int)
        (bl * ((f32)(u32)
        cb - (f32)(u32)
        pb
        )
        +(f32)(u32)
        pb
        )
        ;
        pb = prev[0x61];
        cb = cur2[0x61];
        c02 = (int)
        (bl * ((f32)(u32)
        cb - (f32)(u32)
        pb
        )
        +(f32)(u32)
        pb
        )
        ;
        pb = prev[0x62];
        cb = cur2[0x62];
        c03 = (int)
        (bl * ((f32)(u32)
        cb - (f32)(u32)
        pb
        )
        +(f32)(u32)
        pb
        )
        ;
        pb = prev[0x68];
        cb = cur2[0x68];
        c11 = (int)
        (bl * ((f32)(u32)
        cb - (f32)(u32)
        pb
        )
        +(f32)(u32)
        pb
        )
        ;
        pb = prev[0x69];
        cb = cur2[0x69];
        c12 = (int)
        (bl * ((f32)(u32)
        cb - (f32)(u32)
        pb
        )
        +(f32)(u32)
        pb
        )
        ;
        pb = prev[0x6a];
        cb = cur2[0x6a];
        c13 = (int)
        (bl * ((f32)(u32)
        cb - (f32)(u32)
        pb
        )
        +(f32)(u32)
        pb
        )
        ;
        pb = prev[0xa0];
        cb = cur2[0xa0];
        c2 = (int)
        (bl * ((f32)(u32)
        cb - (f32)(u32)
        pb
        )
        +(f32)(u32)
        pb
        )
        ;
    }
    else
    {
        ofs = slot * 0xa4;
        if ((u32)((lbl_803DD12C[ofs + 0xc1] >> 7) & 1) != 0)
        {
            dir[0] = lbl_803DF06C;
            dir[1] = lbl_803DF06C;
            dir[2] = lbl_803DF06C;
            PSVECNormalize(dir, dir);
            PSMTXMultVecSR(Camera_GetInverseViewMatrix(), dir, dir);
        }
        if ((u32)((lbl_803DD12C[ofs + 0xc1] >> 6) & 1) != 0)
        {
            p3 = lbl_803DD12C + ofs;
            dir[0] = *(f32*)(p3 + 0xa8);
            dir[1] = *(f32*)(p3 + 0xac);
            dir[2] = *(f32*)(p3 + 0xb0);
            r = p3[0x7c];
            g = p3[0x7d];
            b = p3[0x7e];
            c01 = p3[0x84];
            c02 = p3[0x85];
            c03 = p3[0x86];
            c11 = p3[0x8c];
            c12 = p3[0x8d];
            c13 = p3[0x8e];
            c2 = 0xff;
        }
        else
        {
            scale1 = a2 + 1;
            c01 = r * scale1 >> 8;
            c02 = g * scale1 >> 8;
            c03 = b * scale1 >> 8;
            scale2 = b2 + 1;
            c11 = r * scale2 >> 8;
            c12 = g * scale2 >> 8;
            c13 = b * scale2 >> 8;
        }
    }
    *(f32*)(lbl_803DD12C + slot * 0xa4 + 0x90) = dir[0];
    *(f32*)(lbl_803DD12C + slot * 0xa4 + 0x94) = dir[1];
    *(f32*)(lbl_803DD12C + slot * 0xa4 + 0x98) = dir[2];
    lbl_803DD12C[slot * 0xa4 + 0x78] = (u8)r;
    lbl_803DD12C[slot * 0xa4 + 0x79] = (u8)g;
    lbl_803DD12C[slot * 0xa4 + 0x7a] = (u8)b;
    *(f32*)(lbl_803DD12C + slot * 0xa4 + 0x9c) = -dir[0];
    *(f32*)(lbl_803DD12C + slot * 0xa4 + 0xa0) = -dir[1];
    *(f32*)(lbl_803DD12C + slot * 0xa4 + 0xa4) = -dir[2];
    lbl_803DD12C[slot * 0xa4 + 0x80] = (u8)(c01 * (colorScale + 1) >> 8);
    lbl_803DD12C[slot * 0xa4 + 0x81] = (u8)(c02 * (colorScale + 1) >> 8);
    lbl_803DD12C[slot * 0xa4 + 0x82] = (u8)(c03 * (colorScale + 1) >> 8);
    lbl_803DD12C[slot * 0xa4 + 0x88] = (u8)c11;
    lbl_803DD12C[slot * 0xa4 + 0x89] = (u8)c12;
    lbl_803DD12C[slot * 0xa4 + 0x8a] = (u8)c13;
    lbl_803DD12C[slot * 0xa4 + 0xc0] = c2;
}

void renderSunAndMoon(int a, int b, int c, int d, int visible)
{
    SkyRotQ q1;
    SkyRotQ q2;
    f32 vec[3];
    SkyVec3 sunDir;
    SkyVec3 moonDir;
    int v;
    s16* cam;
    f32 far;
    f32 yaw;
    f32 scale;
    f32 sunT;
    f32 moonT;
    f32 moonTC;
    f32 riseT;
    f32 time2;
    u8 vis;
    u8* model;

    cam = Camera_GetCurrentViewSlot();
    sunDir = *(SkyVec3*)lbl_802C1F80;
    moonDir = *(SkyVec3*)lbl_802C1F8C;
    v = 0;
    q1.x = pEXIInputFlag;
    q1.y = pEXIInputFlag;
    q1.z = pEXIInputFlag;
    q1.w = EXIInputFlag;
    q1.rz = 0;
    q1.ry = 0;
    q1.rx = 0;
    q2.x = pEXIInputFlag;
    q2.y = pEXIInputFlag;
    q2.z = pEXIInputFlag;
    q2.w = EXIInputFlag;
    q2.rz = 0;
    q2.ry = 0;
    q2.rx = 0;
    (*gSkyInterface)->getTransitionTimer(&v);
    if (cam != NULL && lbl_803DD12C != NULL)
    {
        far = Camera_GetFarPlane();
        Camera_SetFarPlane(lbl_803DF098, 0);
        Camera_RebuildProjectionMatrix();
        sunT = (((SkyState*)lbl_803DD12C)->timeOfDay - lbl_803DF084) / lbl_803DF09C;
        if (sunT < pEXIInputFlag)
        {
            sunT = pEXIInputFlag;
        }
        else if (sunT > EXIInputFlag)
        {
            sunT = EXIInputFlag;
        }
        if (sunT < lbl_803DF0A0)
        {
            if (sunT < pEXIInputFlag)
            {
                lbl_803DD128 = 0;
            }
            else
            {
                lbl_803DD128 = (u16)(int)(lbl_803DF0A4 * sunT);
            }
        }
        else
        {
            if (sunT > lbl_803DF0A8)
            {
                if (sunT > EXIInputFlag)
                {
                    lbl_803DD128 = 0;
                }
                else
                {
                    lbl_803DD128 = (u16)(int)(lbl_803DF0A4 * (lbl_803DF0A0 - (sunT - lbl_803DF0A8)));
                }
            }
            else
            {
                lbl_803DD128 = 0xff;
            }
        }
        sunT *= lbl_803DF0AC;
        riseT = (((SkyState*)lbl_803DD12C)->timeOfDay - lbl_803DF084) / lbl_803DF0B0;
        if (riseT < pEXIInputFlag)
        {
            riseT = pEXIInputFlag;
        }
        else if (riseT > EXIInputFlag)
        {
            riseT = EXIInputFlag - (riseT - EXIInputFlag);
        }
        scale = -(lbl_803DF0B4 * riseT - EXIInputFlag);
        vec[0] = lbl_803DF0B8 * sunDir.x;
        vec[1] = lbl_803DF0B8 * sunDir.y;
        vec[2] = lbl_803DF0B8 * sunDir.z;
        yaw = ((SkyState*)lbl_803DD12C)->unk1C;
        q1.rx = (u16)(int)
        sunT;
        vecRotateZXY(&q1, vec);
        q1.w = EXIInputFlag;
        q1.rz = (u16)(int)
        yaw;
        q1.ry = 0;
        q1.rx = 0;
        vecRotateZXY(&q1, vec);
        lbl_8030F2C8[0] = vec[0];
        lbl_8030F2C8[1] = vec[1];
        lbl_8030F2C8[2] = vec[2];
        *(f32*)(gSkySunObject + 0xc) = *(f32*)(cam + 0x22) + (f32)(s16)(int)
        vec[0];
        *(f32*)(gSkySunObject + 0x10) = *(f32*)(cam + 0x24) + (f32)(s16)(int)
        vec[1];
        *(f32*)(gSkySunObject + 0x14) = *(f32*)(cam + 0x26) + (f32)(s16)(int)
        vec[2];
        *(f32*)(gSkySunObject + 8) = lbl_803DF0BC * scale;
        *(s16*)gSkySunObject = 0x10000 - cam[0];
        *(s16*)(gSkySunObject + 2) = cam[1];
        *(s16*)(gSkySunObject + 4) = 0;
        gSkySunObject[0x37] = (u8)lbl_803DD128;
        time2 = ((SkyState*)lbl_803DD12C)->timeOfDay;
        if (time2 >= lbl_803DF088)
        {
            moonT = time2 - lbl_803DF088;
        }
        else
        {
            moonT = time2 + lbl_803DF0C0;
        }
        moonTC = moonT / lbl_803DF0B0;
        if (moonTC < pEXIInputFlag)
        {
            moonTC = pEXIInputFlag;
        }
        else if (moonTC > EXIInputFlag)
        {
            moonTC = EXIInputFlag;
        }
        if (moonTC < lbl_803DF0A0)
        {
            if (moonTC < pEXIInputFlag)
            {
                lbl_803DD12A = 0;
            }
            else
            {
                lbl_803DD12A = (u16)(int)(lbl_803DF0A4 * moonTC);
            }
        }
        else
        {
            if (moonTC > lbl_803DF0A8)
            {
                if (moonTC > EXIInputFlag)
                {
                    lbl_803DD12A = 0;
                }
                else
                {
                    lbl_803DD12A = (u16)(int)(lbl_803DF0A4 * (lbl_803DF0A0 - (moonTC - lbl_803DF0A8)));
                }
            }
            else
            {
                lbl_803DD12A = 0xff;
            }
        }
        moonTC *= lbl_803DF0AC;
        riseT = moonT / lbl_803DF0C4;
        if (riseT < pEXIInputFlag)
        {
            riseT = pEXIInputFlag;
        }
        else if (riseT > EXIInputFlag)
        {
            riseT = EXIInputFlag - (riseT - EXIInputFlag);
        }
        scale = -(lbl_803DF0B4 * riseT - EXIInputFlag);
        vec[0] = lbl_803DF0B8 * moonDir.x;
        vec[1] = lbl_803DF0B8 * moonDir.y;
        vec[2] = lbl_803DF0B8 * moonDir.z;
        q2.rx = (u16)(int)
        moonTC;
        vecRotateZXY(&q2, vec);
        q2.w = EXIInputFlag;
        q2.rz = (u16)(int)
        yaw;
        q2.ry = 0;
        q2.rx = 0;
        vecRotateZXY(&q2, vec);
        lbl_8030F2D4[0] = vec[0];
        lbl_8030F2D4[1] = vec[1];
        lbl_8030F2D4[2] = vec[2];
        ((GameObject*)gSkyMoonObject)->anim.localPosX = *(f32*)(cam + 0x22) + (f32)(s16)(int)
        vec[0];
        ((GameObject*)gSkyMoonObject)->anim.localPosY = *(f32*)(cam + 0x24) + (f32)(s16)(int)
        vec[1];
        ((GameObject*)gSkyMoonObject)->anim.localPosZ = *(f32*)(cam + 0x26) + (f32)(s16)(int)
        vec[2];
        ((GameObject*)gSkyMoonObject)->anim.rootMotionScale = lbl_803DF0BC * scale;
        *(s16*)gSkyMoonObject = 0x10000 - cam[0];
        ((GameObject*)gSkyMoonObject)->anim.rotY = cam[1];
        ((GameObject*)gSkyMoonObject)->anim.rotZ = 0;
        vis = 0;
        ((u8*)gSkyMoonObject)[0x37] = (u8)lbl_803DD12A;
        if (gSkySunObject[0x37] != 0)
        {
            if (lbl_803DD12C != NULL)
            {
                vis = (lbl_803DD12C[0x209] >> 7) & 1;
            }
            if (vis == 0 && (u8)visible != 0)
            {
                model = Obj_GetActiveModel(gSkySunObject);
                *(u16*)(model + 0x18) &= ~8;
                objRender(a, b, c, d, gSkySunObject, 1);
            }
        }
        if (((u8*)gSkyMoonObject)[0x37] != 0)
        {
            if (lbl_803DD12C == NULL)
            {
                vis = 0;
            }
            else
            {
                vis = (lbl_803DD12C[0x209] >> 7) & 1;
            }
            if (vis == 0 && (u8)visible != 0)
            {
                model = Obj_GetActiveModel(gSkyMoonObject);
                *(u16*)(model + 0x18) &= ~8;
                objRender(a, b, c, d, gSkyMoonObject, 1);
            }
        }
        Camera_SetFarPlane(far, 0);
        Camera_RebuildProjectionMatrix();
    }
}
#pragma opt_common_subs reset

#pragma opt_common_subs off
void skyFn_8008aee8(void)
{
    int* sky;
    int texA;
    int texB;
    u8* texC;
    s16* cam;
    u8* player;
    int cell;
    u8* tbl;
    u8* p;
    u8* lc;
    u8* ac;
    int idxA;
    int idxB;
    int a;
    int b;
    int hw;
    u32 res;
    int tmp;
    f32 frac;
    f32 t;
    f32 tc;
    f32 u;
    f32 widthF;
    f32 sinProd;
    f32 angle;
    f32 blend;
    f32 v;
    FogColor fogColor;

    fogColor = *(FogColor*)&lbl_803E8458;
    if (lbl_803DD12C != NULL &&
        ((player = Obj_GetPlayerObject()) == NULL ||
            ((cell = coordsToMapCell(*(f32*)(player + 0xc), *(f32*)(player + 0x14))) != 0x30 &&
                cell != 0x2b)))
    {
        sky = *(int**)&lbl_803DD12C;
        frac = ((SkyTimeBlend*)sky)->time / lbl_803DF078;
        t = (frac < pEXIInputFlag) ? pEXIInputFlag : ((frac > EXIInputFlag) ? EXIInputFlag : frac);
        if (t >= pEXIInputFlag && t < lbl_803DF0C8)
        {
            u = t / lbl_803DF0C8;
            ((SkyTimeBlend*)sky)->phase = 0;
        }
        else if (t >= lbl_803DF0C8 && t < lbl_803DF07C)
        {
            u = (t - lbl_803DF0C8) / lbl_803DF0C8;
            ((SkyTimeBlend*)sky)->phase = 1;
        }
        else if (t >= lbl_803DF07C && t < lbl_803DF0CC)
        {
            u = (t - lbl_803DF07C) / lbl_803DF0C8;
            ((SkyTimeBlend*)sky)->phase = 2;
        }
        else if (t >= lbl_803DF0CC && t < lbl_803DF068)
        {
            u = (t - lbl_803DF0CC) / lbl_803DF0C8;
            ((SkyTimeBlend*)sky)->phase = 3;
        }
        else if (t >= lbl_803DF068 && t < lbl_803DF0D0)
        {
            u = (t - lbl_803DF068) / lbl_803DF0C8;
            ((SkyTimeBlend*)sky)->phase = 4;
        }
        else if (t >= lbl_803DF0D0 && t < init_803DF080)
        {
            u = (t - lbl_803DF0D0) / lbl_803DF0C8;
            ((SkyTimeBlend*)sky)->phase = 5;
        }
        else if (t >= init_803DF080 && t < lbl_803DF0D4)
        {
            u = (t - init_803DF080) / lbl_803DF0C8;
            ((SkyTimeBlend*)sky)->phase = 6;
        }
        else if (t >= lbl_803DF0D4 && t <= EXIInputFlag)
        {
            u = (t - lbl_803DF0D4) / lbl_803DF0C8;
            ((SkyTimeBlend*)sky)->phase = 7;
        }
        tc = (u < pEXIInputFlag) ? pEXIInputFlag : ((u > EXIInputFlag) ? EXIInputFlag : u);
        sky = *(int**)&lbl_803DD12C;
        if (((SkyTimeBlend*)sky)->phase != ((SkyTimeBlend*)sky)->prevPhase)
        {
            texA = sky[((SkyTimeBlend*)sky)->phase + 0x87];
            texB = sky[(((SkyTimeBlend*)sky)->phase + 1) % 8 + 0x87];
            if (((SkyTimeBlend*)sky)->texAId != texA)
            {
                textureFree((void*)sky[0]);
                *(void**)lbl_803DD12C = textureLoadAsset(texA);
                ((SkyTimeBlend*)lbl_803DD12C)->texAId = texA;
            }
            sky = *(int**)&lbl_803DD12C;
            if (((SkyTimeBlend*)sky)->texBId != texB)
            {
                textureFree((void*)sky[1]);
                ((SkyTimeBlend*)lbl_803DD12C)->texB = textureLoadAsset(texB);
                ((SkyTimeBlend*)lbl_803DD12C)->texBId = texB;
            }
            ((SkyTimeBlend*)lbl_803DD12C)->prevPhase = (s8)((SkyTimeBlend*)lbl_803DD12C)->phase;
        }
        fn_80069B1C(((SkyTimeBlend*)lbl_803DD12C)->texB, ((SkyTimeBlend*)lbl_803DD12C)->texA, tc,
                    (void*)(*(int**)&lbl_803DD12C)[((SkyTimeBlend*)lbl_803DD12C)->texSel + 2]);
        ((SkyBlendStateFlags*)(lbl_803DD12C + 0x255))->unused80 = 1;
        sky = *(int**)&lbl_803DD12C;
        blend = ((SkyTimeBlend*)sky)->blend;
        if (blend != pEXIInputFlag)
        {
            tmp = sky[((SkyTimeBlend*)sky)->texSel + 2];
            fn_80069B1C((void*)sky[4], (void*)tmp, blend, (void*)tmp);
        }
        sky = *(int**)&lbl_803DD12C;
        idxA = (s16)(sky[((SkyTimeBlend*)sky)->phase + 0x87] - 0xc38) * 6;
        tbl = lbl_8030F31C;
        a = tbl[idxA];
        idxB = (s16)(sky[(((SkyTimeBlend*)sky)->phase + 1) % 8 + 0x87] - 0xc38) * 6;
        b = tbl[idxB];
        gSkyCurrentLightColor = (u8)(int)(tc * (f32)(b - a) + (f32)(u32)a);
        p = tbl + 1;
        a = p[idxA];
        b = p[idxB];
        lc = &gSkyCurrentLightColor;
        lc[1] = (u8)(int)(tc * (f32)(b - a) + (f32)(u32)a);
        p = tbl + 2;
        a = p[idxA];
        b = p[idxB];
        lc[2] = (u8)(int)(tc * (f32)(b - a) + (f32)(u32)a);
        p = tbl + 3;
        a = p[idxA];
        b = p[idxB];
        gSkyCurrentAmbientColor = (u8)(int)(tc * (f32)(b - a) + (f32)(u32)a);
        p = tbl + 4;
        a = p[idxA];
        b = p[idxB];
        ac = &gSkyCurrentAmbientColor;
        ac[1] = (u8)(int)(tc * (f32)(b - a) + (f32)(u32)a);
        p = tbl + 5;
        a = p[idxA];
        b = p[idxB];
        ac[2] = (u8)(int)(tc * (f32)(b - a) + (f32)(u32)a);
        texC = (u8*)sky[((SkyTimeBlend*)sky)->texSel + 2];
        cam = Camera_GetCurrentViewSlot();
        frac = Camera_GetFovY() * lbl_803DF068;
        widthF = (f32)(u32) * (u16*)(texC + 0xc);
        sinProd = widthF * frac / lbl_803DF0D8;
        sinProd *= lbl_803DF0DC;
        sinProd *= mathCosf(lbl_803DF0E0 * (f32) - cam[0x2a] / lbl_803DF0E4);
        angle = widthF * lbl_803DF068 - lbl_803DF0E8 -
            lbl_803DF0DC * (widthF * (f32)cam[0x29]) / lbl_803DF0E4 + sinProd;
        angle *= lbl_803DF0EC;
        (*gSky2Interface)->applyTextColor(0);
        GXSetFog(0, pEXIInputFlag, pEXIInputFlag, pEXIInputFlag, pEXIInputFlag, fogColor);
        selectTexture(texC, 0);
        fn_8007880C();
        GXSetTevOrder(0, 0, 0, 0xff);
        GXSetTevDirect(0);
        GXSetTevColorIn(0, 8, 4, 5, 0xf);
        GXSetTevAlphaIn(0, 7, 7, 7, 4);
        GXSetTevSwapMode(0, 0, 0);
        GXSetTevColorOp(0, 0, 0, 0, 1, 0);
        GXSetTevAlphaOp(0, 0, 0, 0, 1, 0);
        GXSetTexCoordGen2(0, 1, 4, 0x3c, 0, 0x7d);
        GXSetNumIndStages(0);
        GXSetNumChans(0);
        GXSetNumTexGens(1);
        GXSetNumTevStages(1);
        res = getScreenResolution();
        sinProd *= lbl_803DF0B8;
        hw = *(u16*)(texC + 0xc);
        v = angle / (lbl_803DF0EC * (f32)(u32)
        hw
        )
        ;
        skyDrawFn_80075d5c(pEXIInputFlag, v, EXIInputFlag, v - sinProd / (f32)(u32)hw, 0, 0,
                           (res & 0xffff) << 2, (res >> 16) << 2, -0x18f);
    }
}
#pragma opt_common_subs reset

void Sky_func03(int a, int b, u8* cfg)
{
    s16* envp;
    u8* env2;
    u32 mask;
    int i;
    int iofs;
    u8* p4;
    u32 cloudMode;
    u8 vis;
    int tmp;

    envp = (s16*)saveGameGetEnvState();
    if (cfg != NULL && (((Sky2Config*)cfg)->unk58 & 2) != 0)
    {
        switch (((Sky2Config*)cfg)->cloudMode)
        {
        case 0:
        default:
            mask = 0xf;
            break;
        case 1:
            mask = 1;
            break;
        case 2:
            mask = 2;
            break;
        case 3:
            mask = 4;
            break;
        case 4:
            mask = 5;
            break;
        case 5:
            mask = 3;
            break;
        case 6:
            mask = 6;
            break;
        }
        iofs = 0;
        for (i = 0; i < 2; i++)
        {
            if ((mask & (1 << i)) != 0)
            {
                envp[2] = (s16)((Sky2Config*)cfg)->unk24 - 1;
                *(f32*)(lbl_803DD12C + iofs + 0x20) = (f32)(u32)((Sky2Config*)cfg)->lightColorR;
                *(f32*)(lbl_803DD12C + iofs + 0x24) = (f32)(u32)((Sky2Config*)cfg)->lightColorR;
                *(f32*)(lbl_803DD12C + iofs + 0x28) = (f32)(u32)((Sky2Config*)cfg)->lightColorG;
                *(f32*)(lbl_803DD12C + iofs + 0x2c) = (f32)(u32)((Sky2Config*)cfg)->lightColorB;
                *(f32*)(lbl_803DD12C + iofs + 0x30) = (f32)(u32)((Sky2Config*)cfg)->lightColorA;
                *(f32*)(lbl_803DD12C + iofs + 0x34) = (f32)(u32)((Sky2Config*)cfg)->lightColorR;
                *(f32*)(lbl_803DD12C + iofs + 0x38) = (f32)(u32)((Sky2Config*)cfg)->lightColorR;
                *(f32*)(lbl_803DD12C + iofs + 0x3c) = (f32)(u32)((Sky2Config*)cfg)->unk14;
                *(f32*)(lbl_803DD12C + iofs + 0x40) = (f32)(u32)((Sky2Config*)cfg)->unk14;
                *(f32*)(lbl_803DD12C + iofs + 0x44) = (f32)(u32)((Sky2Config*)cfg)->unk15;
                *(f32*)(lbl_803DD12C + iofs + 0x48) = (f32)(u32)((Sky2Config*)cfg)->unk16;
                *(f32*)(lbl_803DD12C + iofs + 0x4c) = (f32)(u32)((Sky2Config*)cfg)->unk17;
                *(f32*)(lbl_803DD12C + iofs + 0x50) = (f32)(u32)((Sky2Config*)cfg)->unk14;
                *(f32*)(lbl_803DD12C + iofs + 0x54) = (f32)(u32)((Sky2Config*)cfg)->unk14;
                *(f32*)(lbl_803DD12C + iofs + 0x58) = (f32)(u32)((Sky2Config*)cfg)->unk1C;
                *(f32*)(lbl_803DD12C + iofs + 0x5c) = (f32)(u32)((Sky2Config*)cfg)->unk1C;
                *(f32*)(lbl_803DD12C + iofs + 0x60) = (f32)(u32)((Sky2Config*)cfg)->unk1D;
                *(f32*)(lbl_803DD12C + iofs + 0x64) = (f32)(u32)((Sky2Config*)cfg)->unk1E;
                *(f32*)(lbl_803DD12C + iofs + 0x68) = (f32)(u32)((Sky2Config*)cfg)->unk1F;
                *(f32*)(lbl_803DD12C + iofs + 0x6c) = (f32)(u32)((Sky2Config*)cfg)->unk1C;
                *(f32*)(lbl_803DD12C + iofs + 0x70) = (f32)(u32)((Sky2Config*)cfg)->unk1C;
                *(f32*)(lbl_803DD12C + iofs + 0xb8) = EXIInputFlag;
                if (((Sky2Config*)cfg)->unk2A != 0)
                {
                    *(f32*)(lbl_803DD12C + iofs + 0xb4) =
                        EXIInputFlag / (lbl_803DF104 * (f32)(u32)((Sky2Config*)cfg)->unk2A);
                }
                else
                {
                    *(f32*)(lbl_803DD12C + iofs + 0xb4) = EXIInputFlag;
                }
                p4 = lbl_803DD12C + iofs;
                if (lbl_803DD12C == NULL)
                {
                    p4[0x76] = 0xff;
                    p4[0x75] = 0xff;
                    p4[0x74] = 0xff;
                }
                else
                {
                    p4[0x74] = p4[0x78];
                    p4[0x75] = lbl_803DD12C[iofs + 0x79];
                    p4[0x76] = lbl_803DD12C[iofs + 0x7a];
                }
                if (((Sky2Config*)cfg)->unk5D != 0)
                {
                    ((SkyBlendStateFlags*)(lbl_803DD12C + iofs + 0xc1))->cloud =
                        (((Sky2Config*)cfg)->unk5D & 1) + 1;
                }
                else
                {
                    ((SkyBlendStateFlags*)(lbl_803DD12C + iofs + 0xc1))->cloud = 0;
                }
            }
            envp++;
            iofs += 0xa4;
        }
        if (((Sky2Config*)cfg)->unk5D != 0)
        {
            skyFn_80088c94(mask, ((Sky2Config*)cfg)->unk5D > 2 ? 1 : 0);
        }
        vis = ((Sky2Config*)cfg)->unk56;
        for (i = 0; i < 2; i++)
        {
            if ((mask & (1 << i)) != 0)
            {
                ((SkyBlendStateFlags*)(lbl_803DD12C + i * 0xa4 + 0xc1))->bit20 = vis;
            }
        }
        ((SkyBlendStateFlags*)(lbl_803DD12C + 0x209))->bit20 =
            ((SkyBlendStateFlags*)(lbl_803DD12C + ((SkyState*)lbl_803DD12C)->currentLightIndex * 0xa4 + 0xc1))->bit20;
        if ((((Sky2Config*)cfg)->unk58 & 1) == 0)
        {
            ((SkyState*)lbl_803DD12C)->skyTextureIds[0] = ((Sky2Config*)cfg)->unk2E + 0xc38;
            ((SkyState*)lbl_803DD12C)->skyTextureIds[1] = ((Sky2Config*)cfg)->unk30 + 0xc38;
            ((SkyState*)lbl_803DD12C)->skyTextureIds[2] = ((Sky2Config*)cfg)->unk32 + 0xc38;
            ((SkyState*)lbl_803DD12C)->skyTextureIds[3] = ((Sky2Config*)cfg)->unk34 + 0xc38;
            ((SkyState*)lbl_803DD12C)->skyTextureIds[4] = ((Sky2Config*)cfg)->unk3E + 0xc38;
            ((SkyState*)lbl_803DD12C)->skyTextureIds[5] = ((Sky2Config*)cfg)->unk40 + 0xc38;
            ((SkyState*)lbl_803DD12C)->skyTextureIds[6] = ((Sky2Config*)cfg)->unk42 + 0xc38;
            ((SkyState*)lbl_803DD12C)->skyTextureIds[7] = ((Sky2Config*)cfg)->unk44 + 0xc38;
            tmp = *(int*)&((SkyState*)lbl_803DD12C)->unk10;
            *(int*)&((SkyState*)lbl_803DD12C)->unk10 =
                *(int*)(lbl_803DD12C + ((SkyState*)lbl_803DD12C)->unk251 * 4 + 8);
            *(int*)(lbl_803DD12C + ((SkyState*)lbl_803DD12C)->unk251 * 4 + 8) = tmp;
            ((SkyState*)lbl_803DD12C)->unk250 = -1;
            if (((SkyState*)lbl_803DD12C)->unk255 < 0)
            {
                ((SkyState*)lbl_803DD12C)->unk23C = EXIInputFlag;
                if (((Sky2Config*)cfg)->unk2A == 0)
                {
                    ((SkyState*)lbl_803DD12C)->unk240 = EXIInputFlag;
                }
                else
                {
                    ((SkyState*)lbl_803DD12C)->unk240 =
                        EXIInputFlag / (lbl_803DF104 * (f32)(u32)((Sky2Config*)cfg)->unk2A);
                }
            }
            else
            {
                ((SkyState*)lbl_803DD12C)->unk23C = pEXIInputFlag;
            }
        }
        cloudMode = ((SkyBlendStateFlags*)(lbl_803DD12C + ((SkyState*)lbl_803DD12C)->currentLightIndex * 0xa4 + 0xc1))->
            cloud;
        if (cloudMode != 0)
        {
            setDrawCloudsAndLights(cloudMode - 1);
        }
        ((SkyBlendStateFlags*)(lbl_803DD12C + 0x209))->unused80 =
            ((SkyBlendStateFlags*)(lbl_803DD12C + ((SkyState*)lbl_803DD12C)->currentLightIndex * 0xa4 + 0xc1))->
            unused80;
        ((SkyBlendStateFlags*)(lbl_803DD12C + 0x209))->bit20 =
            ((SkyBlendStateFlags*)(lbl_803DD12C + ((SkyState*)lbl_803DD12C)->currentLightIndex * 0xa4 + 0xc1))->bit20;
        env2 = saveGameGetEnvState();
        if (getSaveGameLoadStatus() == 0)
        {
            for (i = 0; i < 2; i++)
            {
                if (((SkyBlendStateFlags*)(lbl_803DD12C + i * 0xa4 + 0xc1))->unused80 != 0)
                {
                    env2[0x40] |= (2 << i);
                }
                else
                {
                    env2[0x40] &= ~(2 << i);
                }
            }
        }
    }
}

