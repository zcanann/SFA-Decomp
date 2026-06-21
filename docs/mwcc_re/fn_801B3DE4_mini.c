typedef unsigned char u8;
typedef signed char s8;
typedef short s16;
typedef unsigned int u32;
typedef float f32;

extern f32 lbl_803E492C, lbl_803E4930, lbl_803E4934, lbl_803E4938, lbl_803E493C, lbl_803E4940;
extern f32 gExplosionDebrisAlphaScale, gExplosionDebrisSpeedScale;
extern f32 sqrtf(f32);
extern f32 expf(f32);
extern int randomGetRange(int, int);
extern void Sfx_PlayFromObject(int, int);
extern void Sfx_PlayFromObjectLimited(int, int, int);

void fn_801B3DE4(int obj, u8 b, f32 spd, f32 x, f32 y, f32 z)
{
    int p4c = *(int*)(obj + 0x4c);
    int state = *(int*)(obj + 0xb8);
    int idx;
    int off;
    int e;
    int e14;
    char* p;
    idx = (*(u8*)(state + 0xa58))++;
    off = idx * 0x30;
    *(f32*)((char*)state + off) = x;
    e = state + off;
    *(f32*)((char*)e + 0x4) = y;
    *(f32*)((char*)e + 0x8) = z;
    *(f32*)((char*)e + 0x18) = lbl_803E492C;
    *(f32*)((char*)e + 0xc) = *(f32*)((char*)state + 0x18);
    *(f32*)((char*)e + 0x1c) = spd;
    *(u8*)((char*)e + 0x2d) = b;
    *(int*)((char*)e + 0x10) = 0;
    e14 = state + off;
    *(int*)((char*)e14 + 0x14) = (int)(lbl_803E4930 * sqrtf(spd));
    {
        int v = *(int*)((char*)e14 + 0x14);
        if (v < 0) { v = 0; }
        else if (v > 0x3c) { v = 0x3c; }
        *(int*)((char*)e14 + 0x14) = v;
    }
    if (*(u8*)((char*)e + 0x2d) < 1)
    {
        s8 c = *(s8*)((char*)p4c + 0x19);
        if (c != 0)
        {
            if (c == 2) { Sfx_PlayFromObject(obj, 0x4bf); }
            else if (c == 3) { Sfx_PlayFromObject(obj, 0x4c2); }
            else
            {
                s8 m = *(s8*)(obj + 0xac);
                if (m < 0x3a) { if (m == 0x2c) { goto playLimited; } }
                else if (m < 0x3f) { playLimited: Sfx_PlayFromObjectLimited(obj, 0x4b8, 2); goto done; }
                Sfx_PlayFromObject(obj, 0x203);
            done:;
            }
        }
    }
    *(s16*)((char*)state + idx * 0x30 + 0x28) = randomGetRange(0, 0xffff);
    *(s16*)((char*)state + idx * 0x30 + 0x2a) = randomGetRange(0xc8, 0x12c);
    if ((int)randomGetRange(0, 1) != 0)
        *(s16*)((char*)state + idx * 0x30 + 0x2a) = -*(s16*)((char*)state + idx * 0x30 + 0x2a);
    *(u8*)((char*)state + idx * 0x30 + 0x2c) = randomGetRange(0, 3);
    {
        f32 sp = *(f32*)((char*)e + 0x1c);
        f32 ev = expf((lbl_803E4934 * ((f32)(int) * (int*)((char*)e14 + 0x14) - (f32)(int) * (int*)((char*)e + 0x10))) / (f32)(int) * (int*)((char*)e14 + 0x14));
        f32 d = sp - *(f32*)((char*)e + 0x18);
        f32 t = d * ev;
        *(f32*)((char*)e + 0xc) = sp - gExplosionDebrisSpeedScale * t;
        ev = expf((lbl_803E493C * (f32)(int) * (int*)((char*)e + 0x10)) / (f32)(e = (int) * (int*)((char*)e14 + 0x14)));
        t = lbl_803E4938 * ev;
        p = (char*)state;
        *(s8*)(p + idx * 0x30 + 0x2e) = lbl_803E4938 - gExplosionDebrisAlphaScale * t;
        *(int*)(p + idx * 0x30 + 0x20) = lbl_803E4940;
        *(int*)(p + idx * 0x30 + 0x24) = *(int*)(p + idx * 0x30 + 0x20);
        *(u8*)(p + idx * 0x30 + 0x2f) = 1;
    }
}
