#include "main/sky_80080E58_shared.h"

#pragma peephole off
#pragma scheduling off
int getEnvFxBit2BA(void)
{
    return (u8)GameBit_Get(0x2ba);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void setGameBit2BA(int value)
{
    int bitValue;

    bitValue = value;
    if ((u8)bitValue >= 0x1c) {
        bitValue = 0;
    }
    GameBit_Set(0x2ba, (u8)bitValue);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void envFxFn_800887cc(void)
{
    playerEnvFxFn_80088ad4((u8)GameBit_Get(0x2ba));
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void envFxActFn_800887f8(u8 value)
{
    void *player;
    int masked;

    lbl_803DD140 = value;
    masked = (u8)value;
    masked &= 8;
    if (masked == 0) {
        player = Obj_GetPlayerObject();
        getEnvfxAct(player, player, 0x136, 0);
        getEnvfxAct(player, player, 0x137, 0);
        getEnvfxAct(player, player, 0x143, 0);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void fn_80088870(int a, int b, int c, int d)
{
    lbl_803DD13C = a;
    lbl_803DD130 = b;
    lbl_803DD138 = c;
    lbl_803DD134 = d;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void envFxFn_80088884(void)
{
    u8 a;
    u8 b;
    u8 flags;

    a = (u8)(*(int (**)(int))((char *)*gSHthorntailAnimationInterface + 0x24))(0);
    b = (u8)GameBit_Get(0x2ba);
    if (a != lbl_803DD16C) {
        lbl_803DD16C = a;
        if (a == 0) {
            b++;
            if (b == 0x1c) {
                b = 0;
            }
            GameBit_Set(0x2ba, b);
        }
        if (lbl_803DD140 != 0) {
            lbl_803DD140 |= 0x10;
        }
    }
    flags = lbl_803DD140;
    if ((flags & 0x10) == 0) {
        return;
    }
    flags &= ~0x10;
    lbl_803DD140 = flags;
    if (lbl_803DD130 != 0 && (flags & 0x2) != 0 && GameBit_Get(0x3ac) == 0) {
        if ((lbl_803DD140 & 0x20) != 0) {
            getEnvfxActImmediately(0, 0, (u16)((s16 *)lbl_803DD130)[b], 0);
        } else {
            getEnvfxAct(0, 0, (u16)((s16 *)lbl_803DD130)[b], 0);
        }
    }
    if (lbl_803DD13C != 0 && (lbl_803DD140 & 0x4) != 0) {
        if ((lbl_803DD140 & 0x20) != 0) {
            getEnvfxActImmediately(0, 0, (u16)((s16 *)lbl_803DD13C)[b], 0);
        } else {
            getEnvfxAct(0, 0, (u16)((s16 *)lbl_803DD13C)[b], 0);
        }
    }
    if (lbl_803DD138 != 0 && (lbl_803DD140 & 0x1) != 0 && GameBit_Get(0x3ab) == 0) {
        if ((lbl_803DD140 & 0x20) != 0) {
            getEnvfxActImmediately(0, 0, (u16)((s16 *)lbl_803DD138)[b], 0);
        } else {
            getEnvfxAct(0, 0, (u16)((s16 *)lbl_803DD138)[b], 0);
        }
    }
    playerEnvFxFn_80088ad4(b);
    lbl_803DD140 &= ~0x20;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void loadSunAndMoon(void)
{
    void *moonObj;

    if (lbl_803DD154 == 0) {
        gSkySunObject = Obj_SetupObject(Obj_AllocObjectSetup(0x20, 0x62b), 4, -1, -1, NULL);
        moonObj = Obj_SetupObject(Obj_AllocObjectSetup(0x20, 0x62c), 4, -1, -1, NULL);
        gSkyMoonObject = moonObj;
        lbl_803DD154 = 1;
        ObjModel_SetRenderCallback(Obj_GetActiveModel(moonObj), moonFxCb_80074110);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int getSkyColorFn_80088e08(int slot)
{
    u8 *sky;

    sky = lbl_803DD12C;
    if (sky != NULL) {
        slot *= 0xa4;
        slot += 0xc1;
        return (sky[slot] >> 7) & 1;
    }
    return 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int getSkyColorFn_80088e30(int slot)
{
    u8 *sky;

    sky = lbl_803DD12C;
    if (sky != NULL) {
        return sky[slot * 0xa4 + 0xc0];
    }
    return 0xff;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int getSkyStructField24C(void)
{
    u8 *sky;

    sky = lbl_803DD12C;
    if (sky != NULL) {
        return sky[0x24c];
    }
    return 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void fn_8008904C(u8 *red, u8 *green, u8 *blue)
{
    u8 *color;

    if (lbl_803DD12C != NULL) {
        *red = lbl_803DD178;
        color = &lbl_803DD178;
        *green = color[1];
        *blue = color[2];
        return;
    }
    *red = 0xff;
    *green = 0xff;
    *blue = 0xff;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void fn_8008908C(u8 *ambientRed, u8 *ambientGreen, u8 *ambientBlue, u8 *lightRed,
                 u8 *lightGreen, u8 *lightBlue)
{
    u8 *color;
    u8 red;
    u8 green;
    u8 blue;

    if (lbl_803DD15C != 0) {
        red = lbl_803DD158;
        *ambientRed = red;
        *lightRed = red;
        color = &lbl_803DD158;
        green = color[1];
        *ambientGreen = green;
        *lightGreen = green;
        blue = color[2];
        *ambientBlue = blue;
        *lightBlue = blue;
        return;
    }

    if (lbl_803DD12C != NULL) {
        *ambientRed = lbl_803DD174;
        color = &lbl_803DD174;
        *ambientGreen = color[1];
        *ambientBlue = color[2];
        *lightRed = lbl_803DD170;
        color = &lbl_803DD170;
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
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void *fn_8008912C(void)
{
    return lbl_803DD150;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void skyBuildSunModelMatrix(f32 mtx[3][4])
{
    f32 scale;
    f32 scaleMtx[3][4];

    scale = EXIInputFlag / *(f32 *)(gSkySunObject + 8);
    PSMTXScale(scaleMtx, scale, scale, scale);
    Obj_BuildWorldTransformMatrix(gSkySunObject, mtx, 0);
    PSMTXConcat(mtx, scaleMtx, mtx);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int skyFn_8008919c(int slot)
{
    u8 *sky;

    sky = lbl_803DD12C;
    if (sky == NULL) {
        return 0;
    }

    slot *= 0xa4;
    slot += 0xc1;
    if ((u32)((sky[slot] >> 7) & 1) != 0) {
        return 0;
    }
    return gSkySunObject[0x37];
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void skySetOverrideLightColor(u8 red, u8 green, u8 blue)
{
    u8 *color;

    lbl_803DD158 = red;
    color = &lbl_803DD158;
    color[1] = green;
    color[2] = blue;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void skySetOverrideLightColorEnabled(u8 enabled)
{
    lbl_803DD15C = enabled;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void skySetOverrideLightDirection(f32 x, f32 y, f32 z, f32 intensity)
{
    lbl_8039A7A8[0] = x;
    lbl_8039A7A8[1] = y;
    lbl_8039A7A8[2] = z;
    lbl_803DD160 = intensity;
    PSVECNormalize(lbl_8039A7A8, lbl_8039A7A8);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void skySetOverrideLightDirectionEnabled(u8 enabled)
{
    lbl_803DD164 = enabled;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void skyFn_800894a8(int flags, f32 x, f32 y, f32 z)
{
    int bit;

    if (lbl_803DD12C == NULL) {
        return;
    }
    for (bit = 0; bit < 2; bit++) {
        if ((flags & (1 << bit)) != 0) {
            *(f32 *)(lbl_803DD12C + bit * 0xa4 + 0xa8) = x;
            *(f32 *)(lbl_803DD12C + bit * 0xa4 + 0xac) = y;
            *(f32 *)(lbl_803DD12C + bit * 0xa4 + 0xb0) = z;
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void fn_80089510(int flags, u8 red, u8 green, u8 blue)
{
    int bit;

    if (lbl_803DD12C == NULL) {
        return;
    }
    for (bit = 0; bit < 2; bit++) {
        if ((flags & (1 << bit)) != 0) {
            lbl_803DD12C[bit * 0xa4 + 0x8c] = red;
            lbl_803DD12C[bit * 0xa4 + 0x8d] = green;
            lbl_803DD12C[bit * 0xa4 + 0x8e] = blue;
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void fn_80089578(int flags, u8 red, u8 green, u8 blue)
{
    int bit;

    if (lbl_803DD12C == NULL) {
        return;
    }
    for (bit = 0; bit < 2; bit++) {
        if ((flags & (1 << bit)) != 0) {
            lbl_803DD12C[bit * 0xa4 + 0x84] = red;
            lbl_803DD12C[bit * 0xa4 + 0x85] = green;
            lbl_803DD12C[bit * 0xa4 + 0x86] = blue;
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void skyFn_800895e0(int flags, u8 red, u8 green, u8 blue, u8 m1, u8 m2)
{
    int r1, g1, b1, r2, g2, b2;
    int bit;

    if (lbl_803DD12C == NULL) {
        return;
    }
    r1 = red * m1 >> 8;
    g1 = green * m1 >> 8;
    b1 = blue * m1 >> 8;
    r2 = red * m2 >> 8;
    g2 = green * m2 >> 8;
    b2 = blue * m2 >> 8;
    for (bit = 0; bit < 2; bit++) {
        if ((flags & (1 << bit)) != 0) {
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
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void getTimeOfDay(f32 *time)
{
    u8 *sky;

    sky = lbl_803DD12C;
    if (sky == NULL) {
        *time = pEXIInputFlag;
        return;
    }
    *time = *(f32 *)(sky + 0x20c);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void renderSky(void)
{
    if (gSkySunObject != NULL && gSkyMoonObject != NULL) {
        renderSunAndMoon();
    }
    skyFn_8008a500();
    skyFn_8008a04c();
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void getAmbientColor(int slot, u8 *red, u8 *green, u8 *blue)
{
    u8 *sky;
    int offset;

    sky = lbl_803DD12C;
    if (sky == NULL) {
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
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void textureColorFn_8008991c(int slot, u8 *red, u8 *green, u8 *blue)
{
    u8 *sky;
    int offset;

    sky = lbl_803DD12C;
    if (sky == NULL) {
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
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void modelTextureFn_80089970(int slot)
{
    int offset;
    u8 *sky;

    if (lbl_803DD144 != NULL) {
        offset = slot * 0xa4;
        sky = lbl_803DD12C + offset;
        modelStruct2_setVectors(lbl_803DD144, *(f32 *)(sky + 0x90), *(f32 *)(sky + 0x94),
                                *(f32 *)(sky + 0x98));
        modelLightStruct_setColorsA8AC(lbl_803DD144, lbl_803DD12C[offset + 0x78],
                                       lbl_803DD12C[offset + 0x79],
                                       lbl_803DD12C[offset + 0x7a], 0xff);
    }
    if (lbl_803DD168 != NULL) {
        offset = slot * 0xa4;
        sky = lbl_803DD12C + offset;
        modelStruct2_setVectors(lbl_803DD168, *(f32 *)(sky + 0x9c), *(f32 *)(sky + 0xa0),
                                *(f32 *)(sky + 0xa4));
        modelLightStruct_setColorsA8AC(lbl_803DD168, lbl_803DD12C[offset + 0x80],
                                       lbl_803DD12C[offset + 0x81],
                                       lbl_803DD12C[offset + 0x82], 0xff);
    }
    offset = slot * 0xa4;
    colorFn_8001efe0(0, lbl_803DD12C[offset + 0x88], lbl_803DD12C[offset + 0x89],
                     lbl_803DD12C[offset + 0x8a]);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void *fn_80089A50(void)
{
    return lbl_803DD168;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void *fn_80089A58(void)
{
    return lbl_803DD144;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int getSunPos(f32 *outTime)
{
    f32 time;

    if (lbl_803DD12C == NULL) {
        if (outTime != NULL) {
            *outTime = pEXIInputFlag;
        }
        return 0;
    }

    time = *(f32 *)(lbl_803DD12C + 0x20c);
    if (time >= lbl_803DF088 || time < *(&init_803DF080 + 1)) {
        if (outTime != NULL) {
            if (time >= lbl_803DF088) {
                *outTime = *(&init_803DF080 + 1) + (time - lbl_803DF088);
            } else {
                *outTime = *(&init_803DF080 + 1) - time;
            }
        }
        return 1;
    }

    if (outTime != NULL) {
        *outTime = lbl_803DF088 - time;
    }
    return 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void fn_8008B88C(int *outTimer)
{
    u8 *sky;

    sky = lbl_803DD12C;
    if (sky == NULL) {
        *outTimer = 0;
        return;
    }
    *outTimer = *(int *)(sky + 0x218);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void skyFn_80089710(int flags, u32 enabled, int startComplete)
{
    u8 *sky;
    u32 flagBit;
    u32 stateActive;
    u32 requestedActive;

    sky = lbl_803DD12C;
    if (sky == NULL) {
        return;
    }

    flagBit = 0;
    if ((flags & (1 << flagBit)) != 0) {
        stateActive = ((SkyBlendStateFlags *)(sky + 0xc1))->active;
        requestedActive = (u8)enabled;
        if (stateActive != requestedActive) {
            if (startComplete != 0) {
                *(f32 *)(sky + 0xbc) = EXIInputFlag;
            } else {
                *(f32 *)(sky + 0xbc) = pEXIInputFlag;
            }
        }
        sky = lbl_803DD12C;
        ((SkyBlendStateFlags *)(sky + 0xc1))->active = enabled;
    }

    flagBit = 1;
    if ((flags & (1 << flagBit)) != 0) {
        sky = lbl_803DD12C;
        stateActive = ((SkyBlendStateFlags *)(sky + 0x165))->active;
        requestedActive = (u8)enabled;
        if (stateActive != requestedActive) {
            if (startComplete != 0) {
                *(f32 *)(sky + 0x160) = EXIInputFlag;
            } else {
                *(f32 *)(sky + 0x160) = pEXIInputFlag;
            }
        }
        sky = lbl_803DD12C;
        ((SkyBlendStateFlags *)(sky + 0x165))->active = enabled;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void fn_800897D4(int slot, f32 *x, f32 *y, f32 *z)
{
    u8 *sky;
    int offset;
    f32 fallback;

    if (lbl_803DD12C == NULL) {
        fallback = pEXIInputFlag;
        *x = fallback;
        *y = lbl_803DF06C;
        *z = fallback;
        return;
    }

    offset = slot * 0xa4;
    sky = lbl_803DD12C + offset;
    *x = *(f32 *)(sky + 0x90);
    sky = lbl_803DD12C;
    sky += offset;
    *y = *(f32 *)(sky + 0x94);
    sky = lbl_803DD12C;
    sky += offset;
    *z = *(f32 *)(sky + 0x98);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void objGetColor(int slot, u8 *red, u8 *green, u8 *blue)
{
    u8 *sky;
    int offset;

    sky = lbl_803DD12C;
    if (sky == NULL) {
        *blue = 0xff;
        *green = 0xff;
        *red = 0xff;
    } else {
        offset = slot * 0xa4;
        *red = lbl_803DD12C[offset + 0x78];
        *green = lbl_803DD12C[offset + 0x79];
        *blue = lbl_803DD12C[offset + 0x7a];
    }

    *red = (u8)((*red * colorScale) >> 8);
    *green = (u8)((*green * colorScale) >> 8);
    *blue = (u8)((*blue * colorScale) >> 8);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void dll_06_func0B(int *x, int *y)
{
    u8 *state;
    f32 value;

    state = lbl_803DD184;
    if (state != NULL) {
        value = *(f32 *)(state + 0x14);
        *x = value;
        value = *(f32 *)(lbl_803DD184 + 0x18);
        *y = value;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void dll_06_func0A(int *a, int *b, int *c, f32 *scale)
{
    u8 *state;

    state = lbl_803DD184;
    if (state == NULL) {
        return;
    }
    *a = *(int *)(state + 0x24);
    *b = *(int *)(lbl_803DD184 + 0x28);
    *c = *(int *)(lbl_803DD184 + 0x2c);
    *scale = *(f32 *)(lbl_803DD184 + 0x30c);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void dll_06_func0E(void)
{
    if (lbl_803DD184 == NULL) {
        return;
    }
    if (lbl_803DD180 != 1) {
        lbl_803DD180 = 1;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void dll_06_func0D(void)
{
    if (lbl_803DD184 == NULL) {
        return;
    }
    if (lbl_803DD180 != 2) {
        lbl_803DD180 = 2;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void sky2_initialise(void)
{
    u8 **states;
    u8 *state;

    lbl_803DB610 = -1;
    (&lbl_803DB610)[1] = -1;
    if (lbl_803DD184 != NULL) {
        mm_free(lbl_803DD184);
    }
    states = &lbl_803DD184;
    state = states[1];
    if (state != NULL) {
        mm_free(state);
    }
    lbl_803DD184 = NULL;
    states[1] = NULL;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void fn_8008EDE8(f32 *out)
{
    u8 *state;

    state = lbl_803DD19C;
    if (state == NULL) {
        return;
    }
    out[0] = *(f32 *)(state + 0);
    out[1] = *(f32 *)(lbl_803DD19C + 4);
    out[2] = *(f32 *)(lbl_803DD19C + 8);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int fn_8008B71C(int slot)
{
    u8 *sky;

    sky = lbl_803DD12C;
    if (sky != NULL) {
        slot *= 0xa4;
        slot += 0xc1;
        return (sky[slot] >> 5) & 1;
    }
    return 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void skyTimeToDayHourMinute(f32 time, s16 *days, s16 *hours, s16 *minutes)
{
    s32 remaining;

    remaining = (s32)time;
    *days = remaining / 0x34bc0;
    remaining -= *days * 0x34bc0;
    *hours = remaining / 0xe10;
    remaining -= *hours * 0xe10;
    *minutes = remaining / 0x3c;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void skyGetClockTime(f32 *time)
{
    u8 *sky;

    sky = lbl_803DD12C;
    if (sky == NULL) {
        *time = pEXIInputFlag;
    } else {
        *time = *(s32 *)(sky + 0x210);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int dll_06_func0F(void)
{
    u8 *state;
    f32 y;

    state = lbl_803DD184;
    if (state == NULL) {
        return 0xff;
    }
    y = *(f32 *)(state + 0x14);
    if (y < lbl_803DF138) {
        return 0;
    }
    if (y > lbl_803DF13C) {
        return 0xff;
    }
    return (int)(lbl_803DF118 * ((y - lbl_803DF138) / lbl_803DF140));
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
f32 fn_8008ED88(void)
{
    u8 *state;
    u16 totalFrames;
    u16 currentFrame;

    state = lbl_803DD19C;
    if (state != NULL) {
        totalFrames = *(u16 *)(state + 0x22);
        currentFrame = *(u16 *)(state + 0x20);
        return (f32)(s32)(totalFrames - currentFrame) / (f32)totalFrames;
    }
    return lbl_803DF1A0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int return0_80088758(void) { return 0x0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void doNothing_800887C4(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void doNothing_800887C8(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int return0_8008B7E8(void) { return 0x0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void doNothing_8008B8B0(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void pDll_Sky_setTimeOfDay_nop(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void dll_06_func0C_nop(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int dll_06_func07_ret_0(void) { return 0x0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void sky2_release(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void loadLightFn_8008bbc4(void)
{
    u8 done = 0;

    while (getLoadedFileFlags(0) != 0) {
        padUpdate();
        checkReset();
        if (done) {
            waitNextFrame();
        }
        loadDataFiles();
        dvdCheckError();
        if (done) {
            mmFreeTick(0);
            gameTextRun();
            GXFlush_(1, 0);
        }
        if (lbl_803DC950 != 0) {
            done = 1;
        }
    }
    lbl_803DD164 = 0;
    lbl_803DD15C = 0;
    lbl_803DD158 = 0xff;
    (&lbl_803DD158)[1] = 0xff;
    (&lbl_803DD158)[2] = 0xff;
    if (lbl_803DD144 == NULL) {
        lbl_803DD144 = objCreateLight(0, 1);
        if (lbl_803DD144 != NULL) {
            modelLightStruct_setField50(lbl_803DD144, 4);
            modelStruct2_setVectors(lbl_803DD144, pEXIInputFlag, lbl_803DF06C, pEXIInputFlag);
            modelLightStruct_setColorsA8AC(lbl_803DD144, 0xff, 0xff, 0xff, 0xff);
            modelLightStruct_setColors100104(lbl_803DD144, 0xff, 0xff, 0xff, 0xff);
        }
        lbl_803DD168 = objCreateLight(0, 1);
        if (lbl_803DD168 != NULL) {
            modelLightStruct_setField50(lbl_803DD168, 4);
            modelStruct2_setVectors(lbl_803DD168, pEXIInputFlag, EXIInputFlag, pEXIInputFlag);
            modelLightStruct_setColorsA8AC(lbl_803DD168, 0xff, 0xff, 0xff, 0xff);
            modelLightStruct_setColors100104(lbl_803DD168, 0xff, 0xff, 0xff, 0xff);
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
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void dll_06_func06(int obj) {
    u8 *s = lbl_803DD184;

    if (s != NULL) {
        lbl_803DD180 = 2;
        fn_8005D0BC(obj, (u8) * (int *)(s + 0x24), (u8) * (int *)(s + 0x28),
                    (u8) * (int *)(s + 0x2c), 55);
        s = lbl_803DD184;
        if (*(f32 *)(s + 0x14) == *(f32 *)(s + 0x18)) {
            *(f32 *)(s + 0x14) = *(f32 *)(s + 0x14) - lbl_803DF14C;
        }
        s = lbl_803DD184;
        if (*(f32 *)(s + 0x14) > *(f32 *)(s + 0x18)) {
            *(f32 *)(s + 0x14) = *(f32 *)(s + 0x18) - lbl_803DF14C;
        }
        s = lbl_803DD184;
        fogFn_80070404(*(f32 *)(s + 0x14), *(f32 *)(s + 0x18));
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void dll_06_func08(int obj) {
    u8 *s = lbl_803DD184;
    f32 v;
    int alpha;

    if (s != NULL) {
        if (lbl_803DB750 == 0 && (*(u16 *)(s + 4) & 1) == 0) {
            v = *(f32 *)(s + 0x14);
            if (v < lbl_803DF108) {
                alpha = 255;
            } else if (v > lbl_803DF148) {
                alpha = 0;
            } else {
                alpha = (int)(lbl_803DF118 - lbl_803DF118 * (v / lbl_803DF148));
            }
            setTextColor(obj, (u8) * (int *)(s + 0x24), (u8) * (int *)(s + 0x28),
                         (u8) * (int *)(s + 0x2c), (u8)alpha);
        } else {
            setTextColor(obj, 255, 255, 255, 0);
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void fn_8008DAE8(int obj) {
    u8 *s;
    f32 v;
    int alpha;

    if (lbl_803DD184 == NULL) {
        Obj_SetModelColorOverrideRecursive(obj, 0, 0, 0, 0, 0);
    }
    if (lbl_803DB750 == 0 && (*(u16 *)((s = lbl_803DD184) + 4) & 1) == 0) {
        v = *(f32 *)(s + 0x14);
        if (v < lbl_803DF108) {
            alpha = 255;
        } else if (v > lbl_803DF148) {
            alpha = 0;
        } else {
            alpha = (int)(lbl_803DF118 - lbl_803DF118 * (v / lbl_803DF148));
        }
        Obj_SetModelColorOverrideRecursive(obj, (u8) * (int *)(s + 0x24),
                                           (u8) * (int *)(s + 0x28),
                                           (u8) * (int *)(s + 0x2c), (u8)alpha, 1);
    } else {
        Obj_SetModelColorOverrideRecursive(obj, 0, 0, 0, 0, 0);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void playerEnvFxFn_80088ad4(int idx) {
    void *player;
    int alt;
    s16 val;

    player = Obj_GetPlayerObject();
    if ((void *)lbl_803DD134 == NULL) {
        return;
    }
    if (player == NULL) {
        return;
    }
    if ((lbl_803DD140 & 0x8) == 0) {
        return;
    }
    if (GameBit_Get(944) != 0) {
        return;
    }
    alt = (s8)(idx - 1);
    if (alt < 0) {
        alt = 27;
    }
    val = ((s16 *)lbl_803DD134)[(u8)idx];
    if (val <= 0 || ((s16 *)lbl_803DD134)[(s8)alt] != val) {
        getEnvfxAct(player, player, 310, 0);
        getEnvfxAct(player, player, 311, 0);
        getEnvfxAct(player, player, 323, 0);
    }
    val = ((s16 *)lbl_803DD134)[(u8)idx];
    if (val > 0) {
        if (lbl_803DD140 & 0x20) {
            getEnvfxActImmediately(player, player, (u16)val, 0);
        } else {
            getEnvfxAct(player, player, (u16)val, 0);
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void dll_06_func09(s32 *x, s32 *y, s32 *z) {
    Dll06InterpState *state;
    s32 targetX;
    s32 targetY;
    s32 targetZ;
    s32 oldX;
    s32 oldY;
    s32 oldZ;
    f32 blend;

    blend = lbl_803DF108;
    state = (Dll06InterpState *)lbl_803DD184;
    if (state == NULL) {
        return;
    }
    if (state != NULL && state->active == 0) {
        return;
    }

    oldX = *x;
    oldY = *y;
    oldZ = *z;
    if (state != NULL) {
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
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void sky2_onMapSetup(void) {
    int i;
    void **slot;
    f32 b;
    f32 a;

    lbl_803DB610 = -1;
    (&lbl_803DB610)[1] = -1;
    slot = (void **)&lbl_803DD184;
    a = lbl_803DF190;
    b = lbl_803DF194;
    for (i = 0; i < 2; i++) {
        if (slot[i] == NULL) {
            slot[i] = mmAlloc(792, 23, 0);
        }
        memset(slot[i], 0, 792);
        *(int *)((char *)slot[i] + 0x24) = 255;
        *(int *)((char *)slot[i] + 0x28) = 255;
        *(int *)((char *)slot[i] + 0x2c) = 255;
        *(f32 *)((char *)slot[i] + 0x14) = a;
        *(f32 *)((char *)slot[i] + 0x18) = b;
        *(int *)((char *)slot[i] + 0x30) = 255;
        *(int *)((char *)slot[i] + 0x34) = 255;
        *(int *)((char *)slot[i] + 0x38) = 255;
        *(f32 *)((char *)slot[i] + 0x1c) = a;
        *(f32 *)((char *)slot[i] + 0x20) = b;
        if (lbl_803DB754 != 0) {
            getEnvfxAct(NULL, NULL, 9, 0);
            lbl_803DB754 = 0;
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void skyFn_80088c94(int flags, int mode) {
    u8 *env;
    u8 *sky;

    if ((flags & 1) != 0) {
        if ((u8)mode != 0) {
            ((SkyBlendStateFlags *)(lbl_803DD12C + 0xc1))->unused80 = 1;
        } else {
            ((SkyBlendStateFlags *)(lbl_803DD12C + 0xc1))->unused80 = 0;
        }
    }
    if ((flags & 2) != 0) {
        if ((u8)mode != 0) {
            ((SkyBlendStateFlags *)(lbl_803DD12C + 0x165))->unused80 = 1;
        } else {
            ((SkyBlendStateFlags *)(lbl_803DD12C + 0x165))->unused80 = 0;
        }
    }
    sky = lbl_803DD12C;
    ((SkyBlendStateFlags *)(sky + 0x209))->unused80 =
        ((SkyBlendStateFlags *)(sky + sky[0x24c] * 0xa4 + 0xc1))->unused80;
    env = saveGameGetEnvState();
    if (getSaveGameLoadStatus() == 0) {
        if (((SkyBlendStateFlags *)(lbl_803DD12C + 0xc1))->unused80 != 0) {
            env[0x40] |= 2;
        } else {
            env[0x40] &= ~2;
        }
        if (((SkyBlendStateFlags *)(lbl_803DD12C + 0x165))->unused80 != 0) {
            env[0x40] |= 4;
        } else {
            env[0x40] &= ~4;
        }
    }
}
#pragma scheduling reset
#pragma peephole reset
