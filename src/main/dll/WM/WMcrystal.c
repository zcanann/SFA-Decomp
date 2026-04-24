#include "ghidra_import.h"
#include "main/dll/WM/WMcrystal.h"

extern undefined4 FUN_8000a538();
extern undefined4 FUN_8000b4f0();
extern undefined4 FUN_8000bb38();
extern uint FUN_80020078();
extern undefined4 FUN_800201ac();
extern uint FUN_80022264();
extern void* FUN_8002becc();
extern undefined4 FUN_8002e088();
extern uint FUN_8002e144();
extern int FUN_8002e1f4();
extern int FUN_80036868();
extern undefined4 FUN_800395a4();
extern undefined4 FUN_8003b9ec();
extern undefined4 FUN_800979c0();
extern undefined4 FUN_8009a468();
extern undefined4 FUN_8011f9b8();
extern undefined4 FUN_801dd760();
extern undefined4 FUN_80286830();
extern undefined8 FUN_80286840();
extern undefined4 FUN_8028687c();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_802945e0();
extern undefined4 FUN_80294964();

extern undefined4 DAT_80328658;
extern undefined4 DAT_803286b0;
extern undefined4* DAT_803dd6d4;
extern f64 DOUBLE_803e62a8;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dda58;
extern f32 FLOAT_803dda5c;
extern f32 FLOAT_803e6288;
extern f32 FLOAT_803e628c;
extern f32 FLOAT_803e6290;
extern f32 FLOAT_803e6294;
extern f32 FLOAT_803e6298;
extern f32 FLOAT_803e629c;
extern f32 FLOAT_803e62a0;
extern f32 FLOAT_803e62b4;
extern f32 FLOAT_803e62b8;
extern f32 FLOAT_803e62bc;
extern f32 FLOAT_803e62c0;
extern f32 FLOAT_803e62c4;
extern f32 FLOAT_803e62c8;

/*
 * --INFO--
 *
 * Function: FUN_801dd798
 * EN v1.0 Address: 0x801DD46C
 * EN v1.0 Size: 588b
 * EN v1.1 Address: 0x801DD798
 * EN v1.1 Size: 656b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801dd798(void)
{
  bool bVar1;
  undefined2 *puVar2;
  int iVar3;
  undefined4 *puVar4;
  int iVar5;
  undefined2 *puVar6;
  int iVar7;
  int iVar8;
  undefined8 uVar9;
  int local_48;
  int local_44;
  undefined auStack_40 [8];
  float local_38;
  float local_34;
  float local_30;
  float local_2c;
  undefined8 local_28;
  undefined8 local_20;
  
  uVar9 = FUN_80286840();
  puVar2 = (undefined2 *)((ulonglong)uVar9 >> 0x20);
  iVar5 = (int)uVar9;
  bVar1 = false;
  iVar8 = 0;
  iVar3 = FUN_8002e1f4(&local_44,&local_48);
  for (; local_44 < local_48; local_44 = local_44 + 1) {
    puVar6 = *(undefined2 **)(iVar3 + local_44 * 4);
    if (puVar6[0x23] == 0x3c1) {
      iVar7 = *(int *)(puVar6 + 0x5c);
      if ((*(ushort *)(iVar7 + 0x12) & 2) != 0) {
        if ((*(ushort *)(iVar7 + 0x12) & 1) == 0) {
          if (*(short *)(iVar7 + 0x10) == 4) {
            iVar8 = iVar8 + 1;
            if (puVar6 == puVar2) {
              local_20 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar5 + 0x10) ^ 0x80000000);
              *(float *)(iVar5 + 0xc) = FLOAT_803e6288 * (float)(local_20 - DOUBLE_803e62a8);
              local_28 = (double)(longlong)(int)*(float *)(iVar5 + 0xc);
              *puVar2 = (short)(int)*(float *)(iVar5 + 0xc);
              bVar1 = true;
            }
          }
          else if (puVar6 == puVar2) {
            FUN_8000bb38(0,0x487);
          }
        }
        else if (*(short *)(iVar7 + 0x10) == 3) {
          iVar8 = iVar8 + 1;
          if (puVar6 == puVar2) {
            local_28 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar5 + 0x10) + 1U ^ 0x80000000);
            *(float *)(iVar5 + 0xc) = FLOAT_803e6288 * (float)(local_28 - DOUBLE_803e62a8);
            local_20 = (double)(longlong)(int)*(float *)(iVar5 + 0xc);
            *puVar2 = (short)(int)*(float *)(iVar5 + 0xc);
            bVar1 = true;
          }
        }
        else if (puVar6 == puVar2) {
          FUN_8000bb38(0,0x487);
        }
      }
    }
  }
  if (bVar1) {
    local_34 = FLOAT_803e628c;
    local_30 = FLOAT_803e6290;
    local_2c = FLOAT_803e628c;
    local_38 = FLOAT_803e6294;
    for (local_44 = 0x14; local_44 != 0; local_44 = local_44 + -1) {
      FUN_800979c0((double)FLOAT_803e6298,(double)FLOAT_803e629c,(double)FLOAT_803e629c,
                   (double)FLOAT_803e62a0,puVar2,7,5,7,100,(int)auStack_40,0);
    }
    puVar4 = (undefined4 *)FUN_800395a4((int)puVar2,0);
    if (puVar4 != (undefined4 *)0x0) {
      *puVar4 = 0x100;
    }
  }
  if (iVar8 == 5) {
    if (bVar1) {
      FUN_8000bb38(0,0x7e);
    }
  }
  else if (bVar1) {
    FUN_8000bb38(0,0x409);
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801dda28
 * EN v1.0 Address: 0x801DD6B8
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801DDA28
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801dda28(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b9ec(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801dda5c
 * EN v1.0 Address: 0x801DD6E0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801DDA5C
 * EN v1.1 Size: 1048b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801dda5c(undefined2 *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801dde74
 * EN v1.0 Address: 0x801DD6E4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801DDE74
 * EN v1.1 Size: 420b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801dde74(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801de018
 * EN v1.0 Address: 0x801DD6E8
 * EN v1.0 Size: 592b
 * EN v1.1 Address: 0x801DE018
 * EN v1.1 Size: 504b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801de018(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  short *psVar1;
  uint uVar2;
  undefined2 *puVar3;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  char cVar4;
  char cVar5;
  int iVar6;
  int iVar7;
  double extraout_f1;
  double dVar8;
  double dVar9;
  
  psVar1 = (short *)FUN_80286830();
  dVar9 = extraout_f1;
  uVar2 = FUN_8002e144();
  if ((uVar2 & 0xff) != 0) {
    cVar4 = '\x01';
    iVar7 = 0;
    for (cVar5 = '\0'; cVar5 < '\b'; cVar5 = cVar5 + '\x01') {
      iVar6 = *(int *)(psVar1 + 0x26);
      puVar3 = FUN_8002becc(0x38,0x27b);
      dVar8 = (double)FUN_802945e0();
      *(float *)(puVar3 + 4) = (float)(dVar9 * dVar8 + (double)*(float *)(psVar1 + 6));
      *(undefined4 *)(puVar3 + 6) = *(undefined4 *)(psVar1 + 8);
      dVar8 = (double)FUN_80294964();
      *(float *)(puVar3 + 8) = (float)(dVar9 * dVar8 + (double)*(float *)(psVar1 + 10));
      *(undefined *)(puVar3 + 2) = *(undefined *)(iVar6 + 4);
      *(byte *)((int)puVar3 + 5) = *(byte *)(iVar6 + 5) & 0xfe | 4;
      *(undefined *)(puVar3 + 3) = *(undefined *)(iVar6 + 6);
      *(undefined *)((int)puVar3 + 7) = 0x1e;
      puVar3[0xc] = 0xffff;
      puVar3[0xd] = 0x64c;
      puVar3[0xe] = (&DAT_803286b0)[cVar4];
      puVar3[0x18] = *(undefined2 *)(cVar4 * 2 + -0x7fcd7960);
      *(char *)(puVar3 + 0x15) = (char)((uint)(*psVar1 + iVar7 + 0x8000) >> 8);
      *(undefined *)(puVar3 + 0x19) = 1;
      FUN_8002e088(dVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar3,5,0xff,
                   0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
      cVar4 = cVar4 + '\x01';
      if ('\a' < cVar4) {
        cVar4 = '\0';
      }
      iVar7 = iVar7 + 0x2000;
    }
  }
  FUN_8028687c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801de210
 * EN v1.0 Address: 0x801DD938
 * EN v1.0 Size: 468b
 * EN v1.1 Address: 0x801DE210
 * EN v1.1 Size: 484b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801de210(int param_1,undefined4 param_2,int param_3)
{
  byte bVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  int local_28;
  int local_24;
  int local_20;
  int local_1c [3];
  
  iVar5 = *(int *)(param_1 + 0xb8);
  *(undefined *)(param_3 + 0x56) = 0;
  iVar4 = 0;
  do {
    if ((int)(uint)*(byte *)(param_3 + 0x8b) <= iVar4) {
      return 0;
    }
    bVar1 = *(byte *)(param_3 + iVar4 + 0x81);
    if (bVar1 == 2) {
      iVar2 = FUN_8002e1f4(&local_20,local_1c);
      piVar3 = (int *)(iVar2 + local_20 * 4);
      for (; local_20 < local_1c[0]; local_20 = local_20 + 1) {
        if ((*piVar3 != param_1) && (*(short *)(*piVar3 + 0x46) == 0x282)) {
          iVar2 = *(int *)(iVar2 + local_20 * 4);
          (**(code **)(**(int **)(iVar2 + 0x68) + 0x20))(iVar2,2);
          break;
        }
        piVar3 = piVar3 + 1;
      }
      *(byte *)(iVar5 + 0x26) = *(byte *)(iVar5 + 0x26) | 0x10;
    }
    else if (bVar1 < 2) {
      if (bVar1 != 0) {
        *(byte *)(iVar5 + 0x26) = *(byte *)(iVar5 + 0x26) | 1;
        (**(code **)(*DAT_803dd6d4 + 0x50))(0x44,1,0,0);
      }
    }
    else if (bVar1 < 4) {
      iVar2 = FUN_8002e1f4(&local_28,&local_24);
      piVar3 = (int *)(iVar2 + local_28 * 4);
      for (; local_28 < local_24; local_28 = local_28 + 1) {
        if ((*piVar3 != param_1) && (*(short *)(*piVar3 + 0x46) == 0x282)) {
          iVar2 = *(int *)(iVar2 + local_28 * 4);
          (**(code **)(**(int **)(iVar2 + 0x68) + 0x20))(iVar2,1);
          break;
        }
        piVar3 = piVar3 + 1;
      }
    }
    iVar4 = iVar4 + 1;
  } while( true );
}

/*
 * --INFO--
 *
 * Function: FUN_801de3f4
 * EN v1.0 Address: 0x801DDB0C
 * EN v1.0 Size: 48b
 * EN v1.1 Address: 0x801DE3F4
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801de3f4(void)
{
  FUN_8000a538((int *)0xf0,0);
  FUN_8011f9b8(0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801de424
 * EN v1.0 Address: 0x801DDB3C
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801DE424
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801de424(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b9ec(param_1);
  }
  return;
}
