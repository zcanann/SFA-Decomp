#include "ghidra_import.h"
#include "main/dll/CF/CFTreasSharpy.h"

extern undefined4 FUN_80006b0c();
extern undefined4 FUN_80006b14();
extern undefined4 FUN_80017a78();
extern undefined4 FUN_800305f8();
extern undefined4 FUN_80135814();
extern undefined4 FUN_8018dc28();
extern undefined4 FUN_80286840();
extern undefined4 FUN_8028688c();

extern u32 GameBit_Get(int bit);
extern void Obj_SetActiveModelIndex(int obj, int idx);
extern void ObjAnim_SetCurrentMove(int obj, int move, f32 f, int p4);
extern u32 randomGetRange(int min, int max);
extern void CFCrate_SeqFn(void);

extern undefined4 DAT_803dca50;
extern undefined4* DAT_803dd708;
extern f64 DOUBLE_803e4ac0;
extern f32 FLOAT_803e4a70;
extern f32 FLOAT_803e4a84;
extern f32 FLOAT_803e4a8c;
extern f32 FLOAT_803e4a94;
extern f32 FLOAT_803e4ac8;
extern f32 FLOAT_803e4acc;
extern f32 FLOAT_803e4ad0;
extern f32 FLOAT_803e4ad4;
extern f32 FLOAT_803e4ad8;
extern f32 FLOAT_803e4ae0;

extern void *lbl_803DBDE8;

extern f32 lbl_803E3DD8;
extern f32 lbl_803E3DEC;
extern f32 lbl_803E3DF4;
extern f32 lbl_803E3DFC;
extern f64 lbl_803E3E28;
extern f32 lbl_803E3E30;
extern f32 lbl_803E3E34;
extern f32 lbl_803E3E38;
extern f32 lbl_803E3E3C;
extern f32 lbl_803E3E40;

/*
 * --INFO--
 *
 * Function: cfccrate_init
 * EN v1.0 Address: 0x8018E0A4
 * EN v1.0 Size: 1560b
 */
#pragma scheduling off
#pragma peephole off
void cfccrate_init(int obj, int aux)
{
    int state;
    short id;
    f32 zeroF;

    id = *(short *)(aux + 0x0);
    state = *(int *)(obj + 0xb8);
    zeroF = lbl_803E3DD8;
    *(f32 *)(state + 0x2c) = zeroF;

    switch (id) {
    case 0x2bb:
        *(short *)(obj + 0) = (short)((s8)*(u8 *)(aux + 0x18) << 8);
        *(short *)(obj + 2) = *(short *)(aux + 0x1a);
        *(short *)(obj + 4) = *(short *)(aux + 0x1c);
        *(f32 *)(obj + 8) = zeroF;
        break;
    case 0x1d0:
    case 0x1d1:
    case 0x1d7:
    case 0x1e6:
    case 0x201:
    case 0x23b:
    case 0x492:
    case 0x78b:
    case 0x78c:
        *(short *)(obj + 0) = (short)((s8)*(u8 *)(aux + 0x18) << 8);
        break;
    case 0x726:
        *(int *)(obj + 0xbc) = (int)&CFCrate_SeqFn;
        *(short *)(obj + 0) = (short)((s8)*(u8 *)(aux + 0x18) << 8);
        break;
    case 0x71b:
        *(short *)(state + 0x36) = *(short *)(aux + 0x1a);
        break;
    case 0x6be:
        *(short *)(obj + 0) = (short)((s8)*(u8 *)(aux + 0x18) << 8);
        *(u8 *)(state + 0x3e) = 0;
        *(short *)(state + 0x3a) = *(short *)(aux + 0x20);
        break;
    case 0x828:
        *(short *)(obj + 0) = (short)((s8)*(u8 *)(aux + 0x18) << 8);
        *(u8 *)(state + 0x3e) = 0;
        *(short *)(state + 0x3a) = *(short *)(aux + 0x20);
        if ((GameBit_Get(*(short *)(state + 0x3a)) != 0) && (*(u8 *)(state + 0x3e) == 0)) {
            *(short *)(obj + 4) = 0x7fff;
            *(u8 *)(state + 0x3e) = 1;
        }
        break;
    case 0x6bf:
        *(short *)(obj + 0) = (short)((s8)*(u8 *)(aux + 0x18) << 8);
        *(short *)(obj + 2) = *(short *)(aux + 0x1a);
        *(short *)(state + 0x3a) = *(short *)(aux + 0x20);
        break;
    case 0x708:
        *(s8 *)(obj + 0xad) = (s8)*(short *)(aux + 0x1a);
        *(short *)(state + 0x38) = *(short *)(aux + 0x20);
        if ((s8)*(u8 *)(obj + 0xad) >= 3) {
            *(s8 *)(obj + 0xad) = 0;
        }
        Obj_SetActiveModelIndex(obj, *(s8 *)(obj + 0xad));
        break;
    case 0x6fc:
        *(short *)(state + 0x38) = *(short *)(aux + 0x20);
        break;
    case 0x622:
        *(short *)(obj + 0) = (short)((s8)*(u8 *)(aux + 0x18) << 8);
        *(short *)(state + 0x38) = *(short *)(aux + 0x20);
        break;
    case 0x6b4:
        *(short *)(obj + 0) = (short)((s8)*(u8 *)(aux + 0x18) << 8);
        *(short *)(obj + 2) = *(short *)(aux + 0x1a);
        ObjAnim_SetCurrentMove(obj, 0, lbl_803E3E30, 0);
        break;
    case 0x66c:
        *(short *)(obj + 0) = (short)((s8)*(u8 *)(aux + 0x18) << 8);
        *(short *)(state + 0x38) = *(short *)(aux + 0x20);
        break;
    case 0x216:
        *(short *)(obj + 0) = (short)((s8)*(u8 *)(aux + 0x18) << 8);
        *(short *)(obj + 2) = *(short *)(aux + 0x1a);
        break;
    case 0x4bf:
        *(short *)(obj + 0) = (short)((s8)*(u8 *)(aux + 0x18) << 8);
        *(u8 *)(obj + 0xad) = *(u8 *)(aux + 0x19);
        *(short *)(state + 0x38) = *(short *)(aux + 0x20);
        if (GameBit_Get(*(short *)(state + 0x38)) != 0) {
            *(f32 *)(obj + 0x10) = lbl_803E3DFC + *(f32 *)(aux + 0xc);
        }
        break;
    case 0x8e:
        *(short *)(obj + 0) = 0;
        *(short *)(obj + 2) = 0;
        if (*(short *)(aux + 0x1c) >= 0x3e8) {
            *(f32 *)(obj + 8) = zeroF / ((f32)(s32)*(short *)(aux + 0x1c) / lbl_803E3DF4);
        } else {
            *(f32 *)(obj + 8) = lbl_803E3E34;
        }
        *(u8 *)(state + 0x3e) = 0;
        *(f32 *)(state + 0x4) = *(f32 *)(aux + 0x8);
        *(f32 *)(state + 0x8) = *(f32 *)(aux + 0xc);
        *(f32 *)(state + 0xc) = *(f32 *)(aux + 0x10);
        *(f32 *)(state + 0x14) = *(f32 *)(state + 0x18) = lbl_803E3E30;
        *(f32 *)(state + 0x28) = lbl_803E3DF4;
        *(f32 *)(state + 0x20) = lbl_803E3E38;
        *(f32 *)(state + 0x1c) = *(f32 *)(state + 0x24) = lbl_803E3DEC;
        *(short *)(obj + 4) = 0;
        *(int *)(obj + 0xbc) = (int)&CFCrate_SeqFn;
        break;
    case 0x7de:
        *(short *)(obj + 0) = (short)((s8)*(u8 *)(aux + 0x18) << 8);
        *(short *)(obj + 2) = 0;
        if (*(short *)(aux + 0x1c) >= 0x3e8) {
            *(f32 *)(obj + 8) = zeroF / ((f32)(s32)*(short *)(aux + 0x1c) / lbl_803E3DF4);
        } else {
            *(f32 *)(obj + 8) = zeroF;
        }
        *(f32 *)(state + 0x24) = (f32)(s32)*(short *)(aux + 0x1a);
        *(short *)(state + 0x38) = *(short *)(aux + 0x20);
        if (GameBit_Get(*(short *)(state + 0x38)) != 0) {
            *(f32 *)(state + 0x24) = *(f32 *)(state + 0x24) * lbl_803E3E3C;
        }
        break;
    case 0xd7:
        *(short *)(obj + 0) = (short)((s8)*(u8 *)(aux + 0x18) << 8);
        *(f32 *)(obj + 8) = zeroF;
        *(u8 *)(state + 0x3e) = 0;
        *(f32 *)(state + 0x4) = *(f32 *)(aux + 0x8);
        *(f32 *)(state + 0x8) = *(f32 *)(aux + 0xc);
        *(f32 *)(state + 0xc) = *(f32 *)(aux + 0x10);
        *(f32 *)(state + 0x1c) = *(f32 *)(state + 0x24) = *(f32 *)(state + 0x20) = *(f32 *)(state + 0x28) = *(f32 *)(state + 0x14) = *(f32 *)(state + 0x18) = lbl_803E3E30;
        *(int *)(obj + 0xbc) = (int)&CFCrate_SeqFn;
        break;
    case 0x125:
        *(short *)(obj + 0) = 0;
        *(short *)(obj + 2) = 0;
        *(short *)(obj + 4) = 0;
        *(f32 *)(obj + 8) = zeroF;
        *(int *)(obj + 0xf4) = 0;
        *(int *)(obj + 0xf8) = 0;
        *(f32 *)(state + 0x24) = lbl_803E3E40;
        *(f32 *)(state + 0x1c) = lbl_803E3DEC;
        *(short *)(state + 0x32) = 0;
        *(short *)(state + 0x34) = (short)randomGetRange(0x3e8, 0x1388);
        *(u8 *)(state + 0x3f) = 1;
        *(int *)(obj + 0xbc) = (int)&CFCrate_SeqFn;
        break;
    case 0x10d:
        *(int *)(obj + 0x54) = 0;
        if (*(short *)(aux + 0x1a) == 0) {
            *(int *)(state + 0x44) = (int)&lbl_803DBDE8;
            *(u8 *)(state + 0x40) = 1;
        }
        *(u16 *)(state + 0x48) = (u16)*(short *)(aux + 0x1c);
        *(short *)(state + 0x3c) = (short)*(u16 *)(state + 0x48);
        break;
    }
}

/*
 * --INFO--
 *
 * Function: FUN_8018e0a8
 * EN v1.0 Address: 0x8018E0A8
 * EN v1.0 Size: 952b
 * EN v1.1 Address: 0x8018EC40
 * EN v1.1 Size: 992b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018e0a8(void)
{
  byte bVar1;
  undefined2 *puVar2;
  int *piVar3;
  int iVar4;
  short sVar5;
  uint uVar6;
  int iVar7;
  undefined2 local_38;
  undefined2 local_36;
  undefined2 local_34;
  float local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  
  puVar2 = (undefined2 *)FUN_80286840();
  iVar7 = *(int *)(puVar2 + 0x5c);
  iVar4 = *(int *)(puVar2 + 0x26);
  uVar6 = 0;
  if (*(short *)(iVar7 + 10) == 0x11) {
    FUN_80135814();
  }
  bVar1 = *(byte *)(iVar4 + 0x28);
  if (bVar1 == 2) {
    sVar5 = *(short *)(iVar7 + 8);
    if (sVar5 == 0) {
      uVar6 = 0x200001;
    }
    if (sVar5 == 1) {
      uVar6 = 1;
    }
    if (sVar5 == 2) {
      uVar6 = 1;
    }
  }
  else if (bVar1 < 2) {
    if (bVar1 == 0) {
      sVar5 = *(short *)(iVar7 + 8);
      if (sVar5 == 0) {
        uVar6 = 2;
      }
      if (sVar5 == 1) {
        uVar6 = 2;
      }
      if (sVar5 == 2) {
        uVar6 = 2;
      }
    }
    else {
      sVar5 = *(short *)(iVar7 + 8);
      if (sVar5 == 0) {
        uVar6 = 4;
      }
      if (sVar5 == 1) {
        uVar6 = 4;
      }
      if (sVar5 == 2) {
        uVar6 = 4;
      }
    }
  }
  else if (bVar1 < 4) {
    uVar6 = 0;
  }
  else {
    uVar6 = 2;
  }
  if ((uVar6 & 1) == 0) {
    sVar5 = *(short *)(iVar7 + 8);
    if (sVar5 == 0) {
      if (*(short *)(iVar7 + 0xe) < 1) {
        (**(code **)(*DAT_803dd708 + 8))(puVar2,(int)*(short *)(iVar7 + 10),0,uVar6,0xffffffff,0);
      }
      else {
        for (sVar5 = 0; sVar5 < *(short *)(iVar7 + 0xe); sVar5 = sVar5 + 1) {
          (**(code **)(*DAT_803dd708 + 8))(puVar2,(int)*(short *)(iVar7 + 10),0,uVar6,0xffffffff,0);
        }
      }
    }
    else if (sVar5 == 1) {
      piVar3 = (int *)FUN_80006b14((int)*(short *)(iVar7 + 10) + 0x58U & 0xffff);
      if (*(short *)(iVar7 + 0xe) < 1) {
        (**(code **)(*piVar3 + 4))(puVar2,0,0,uVar6,0xffffffff,0);
      }
      else {
        for (sVar5 = 0; sVar5 < *(short *)(iVar7 + 0xe); sVar5 = sVar5 + 1) {
          (**(code **)(*piVar3 + 4))(puVar2,0,0,uVar6,0xffffffff,0);
        }
      }
      FUN_80006b0c((undefined *)piVar3);
    }
    else if (sVar5 == 2) {
      piVar3 = (int *)FUN_80006b14((int)*(short *)(iVar7 + 10) + 0xabU & 0xffff);
      if (*(short *)(iVar7 + 0xe) < 1) {
        (**(code **)(*piVar3 + 4))(puVar2,0,0,uVar6,0xffffffff,*(ushort *)(iVar7 + 10) & 0xff,0);
      }
      else {
        for (sVar5 = 0; sVar5 < *(short *)(iVar7 + 0xe); sVar5 = sVar5 + 1) {
          (**(code **)(*piVar3 + 4))(puVar2,0,0,uVar6,0xffffffff,*(ushort *)(iVar7 + 10) & 0xff,0);
        }
      }
      FUN_80006b0c((undefined *)piVar3);
    }
  }
  else {
    local_2c = *(undefined4 *)(puVar2 + 6);
    local_28 = *(undefined4 *)(puVar2 + 8);
    local_24 = *(undefined4 *)(puVar2 + 10);
    local_38 = *puVar2;
    local_34 = puVar2[2];
    local_36 = puVar2[1];
    local_30 = FLOAT_803e4ae0;
    if (*(short *)(iVar7 + 0xe) < 1) {
      (**(code **)(*DAT_803dd708 + 8))
                (puVar2,(int)*(short *)(iVar7 + 0xc),&local_38,uVar6,0xffffffff,0);
    }
    else {
      for (sVar5 = 0; sVar5 < *(short *)(iVar7 + 0xe); sVar5 = sVar5 + 1) {
        (**(code **)(*DAT_803dd708 + 8))
                  (puVar2,(int)*(short *)(iVar7 + 10),&local_38,uVar6,0xffffffff,0);
      }
    }
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: cfccrate_release
 * EN v1.0 Address: 0x8018E6BC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8018E69C
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void cfccrate_release(void)
{
}

/*
 * --INFO--
 *
 * Function: cfccrate_initialise
 * EN v1.0 Address: 0x8018E6C0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8018E6A0
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void cfccrate_initialise(void)
{
}

/*
 * --INFO--
 *
 * Function: fxemit_getExtraSize
 * EN v1.0 Address: 0x8018EC20
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8018ED50
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int fxemit_getExtraSize(void)
{
  return 0x20;
}

/*
 * --INFO--
 *
 * Function: fxemit_func08
 * EN v1.0 Address: 0x8018EC28
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8018ED58
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int fxemit_func08(void)
{
  return 0;
}

/*
 * --INFO--
 *
 * Function: fxemit_hitDetect
 * EN v1.0 Address: 0x8018EC90
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8018EDC0
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fxemit_hitDetect(void)
{
}
