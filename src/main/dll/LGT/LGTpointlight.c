#include "ghidra_import.h"
#include "main/dll/LGT/LGTpointlight.h"

extern int fn_8001F4C8();
extern void fn_8001DB2C();
extern void fn_8001DD88();
extern void fn_8001DAF0();
extern void fn_8001DA18();
extern void fn_8001DC38();
extern void fn_8001DB6C();
extern void fn_8001D620();
extern void fn_8001DAB8();
extern void fn_8001DB54();
extern void fn_8001D730();
extern void fn_8001D714();

extern u8 lbl_802C2488[];
extern f64 lbl_803E5E48;
extern f64 lbl_803E5E50;
extern f32 lbl_803E5E08;
extern f32 lbl_803E5E0C;
extern f32 lbl_803E5E10;
extern f32 lbl_803E5E20;
extern f32 lbl_803E5E24;
extern f32 lbl_803E5E28;
extern f32 lbl_803E5E2C;
extern f32 lbl_803E5E30;
extern f32 lbl_803E5E34;
extern f32 lbl_803E5E38;
extern f32 lbl_803E5E3C;
extern f32 lbl_803E5E40;

/*
 * --INFO--
 *
 * Function: lightsource_init
 * EN v1.0 Address: 0x801F37CC
 * EN v1.0 Size: 1112b
 */
void lightsource_init(undefined2 *obj,int mapData)
{
  ushort flags;
  int lightIndex;
  int temp;
  int colorBase;
  int *state;
  u8 *colors;
  undefined4 local_48;
  uint uStack_44;
  longlong local_40;
  undefined4 local_38;
  uint uStack_34;
  longlong local_30;
  undefined4 local_28;
  uint uStack_24;
  longlong local_20;

  state = *(int **)(obj + 0x5c);
  colors = lbl_802C2488;
  *obj = (short)(((int)*(s8 *)(mapData + 0x18) & 0x3fU) << 10);
  if (*(short *)(mapData + 0x1a) < 1) {
    *(float *)(obj + 4) = lbl_803E5E24;
  }
  else {
    uStack_44 = (int)*(short *)(mapData + 0x1a) ^ 0x80000000;
    local_48 = 0x43300000;
    *(float *)(obj + 4) =
        (float)((double)CONCAT44(0x43300000,uStack_44) - lbl_803E5E48) / lbl_803E5E20;
  }

  *(undefined *)(state + 5) = *(undefined *)(mapData + 0x19);
  state[4] = (int)*(short *)(mapData + 0x1e);
  *(undefined *)((int)state + 0x15) = 1;
  if ((*(ushort *)(mapData + 0x1c) & 0x20) == 0) {
    *(undefined *)((int)state + 0x16) = 3;
  }
  else {
    *(undefined *)((int)state + 0x16) = 0;
  }
  if ((*(byte *)(mapData + 0x22) & 1) == 0) {
    *(undefined *)((int)state + 0x19) = 0;
  }
  else {
    *(undefined *)((int)state + 0x19) = 1;
  }

  if (*(char *)(state + 5) == '\0') {
    *(undefined *)((int)state + 0x17) = 1;
    flags = *(ushort *)(mapData + 0x1c);
    if ((flags & 4) == 0) {
      if ((flags & 8) == 0) {
        if ((flags & 0x10) == 0) {
          if ((flags & 1) != 0) {
            *(undefined *)((int)state + 0x16) = 6;
          }
        }
        else {
          *(undefined *)((int)state + 0x15) = 6;
        }
      }
      else {
        *(undefined *)((int)state + 0x15) = 8;
      }
    }
    else {
      *(undefined *)((int)state + 0x15) = 4;
    }
  }

  if ((*(ushort *)(mapData + 0x1c) & 0x40) == 0) {
    *state = 0;
  }
  else {
    if (*state == 0) {
      temp = fn_8001F4C8(obj,1);
      *state = temp;
      if (*state != 0) {
        fn_8001DB2C(*state,2);
      }
    }
    if (*state != 0) {
      if ((obj[0x23] == 0x705) || (obj[0x23] == 0x712)) {
        fn_8001DD88((double)lbl_803E5E0C,(double)lbl_803E5E0C,(double)lbl_803E5E0C);
      }
      else {
        fn_8001DD88((double)lbl_803E5E0C,(double)lbl_803E5E28,(double)lbl_803E5E0C);
      }

      colorBase = (uint)*(byte *)((int)state + 0x15) * 3;
      fn_8001DAF0(*state,colors[colorBase],colors[colorBase + 1],colors[colorBase + 2],0xff);
      colorBase = (uint)*(byte *)((int)state + 0x15) * 3;
      fn_8001DA18(*state,colors[colorBase],colors[colorBase + 1],colors[colorBase + 2],0xff);
      fn_8001DC38((double)lbl_803E5E2C,(double)lbl_803E5E30,*state);
      fn_8001DB6C((double)lbl_803E5E0C,*state,1);
      fn_8001D620(*state,1,3);

      colorBase = (uint)*(byte *)((int)state + 0x15) * 3;
      uStack_44 = colors[colorBase];
      local_48 = 0x43300000;
      temp = (int)(lbl_803E5E34 *
                   (float)((double)CONCAT44(0x43300000,uStack_44) - lbl_803E5E50));
      local_40 = (longlong)temp;
      uStack_34 = colors[colorBase + 1];
      local_38 = 0x43300000;
      lightIndex = (int)(lbl_803E5E34 *
                         (float)((double)CONCAT44(0x43300000,uStack_34) - lbl_803E5E50));
      local_30 = (longlong)lightIndex;
      uStack_24 = colors[colorBase + 2];
      local_28 = 0x43300000;
      colorBase = (int)(lbl_803E5E34 *
                        (float)((double)CONCAT44(0x43300000,uStack_24) - lbl_803E5E50));
      local_20 = (longlong)colorBase;
      fn_8001DAB8(*state,temp,lightIndex,colorBase,0xff);
      fn_8001DB54(*state,1);

      if ((*(ushort *)(mapData + 0x1c) & 0x80) != 0) {
        lightIndex = (uint)*(byte *)((int)state + 0x15) * 3;
        if ((obj[0x23] == 0x705) || (obj[0x23] == 0x712)) {
          fn_8001D730((double)(lbl_803E5E38 * lbl_803E5E3C * *(float *)(obj + 4)),
                      *state,0,colors[lightIndex],colors[lightIndex + 1],colors[lightIndex + 2],
                      0x8c);
        }
        else {
          fn_8001D730((double)(lbl_803E5E3C * *(float *)(obj + 4)),
                      *state,0,colors[lightIndex],colors[lightIndex + 1],colors[lightIndex + 2],
                      0x8c);
        }
        fn_8001D714((double)lbl_803E5E40,*state);
      }
    }
  }

  if ((*(ushort *)(mapData + 0x1c) & 2) != 0) {
    *(undefined *)((int)state + 0x15) = 0;
  }
  obj[0x58] = obj[0x58] | 0x2000;
  state[1] = (int)lbl_803E5E10;
  state[2] = (int)lbl_803E5E08;
  return;
}

/* Trivial 4b 0-arg blr leaves. */
void lightsource_release(void) {}
void lightsource_initialise(void) {}
void wmworm_hitDetect(void) {}

/* 8b "li r3, N; blr" returners. */
int wmworm_getExtraSize(void) { return 0x1c; }
int wmworm_func08(void) { return 0x0; }
