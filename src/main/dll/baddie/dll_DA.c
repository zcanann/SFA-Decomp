#include "ghidra_import.h"
#include "main/dll/baddie/dll_DA.h"

extern undefined4 FUN_80006c64();
extern undefined4 FUN_80006c84();
extern undefined4 FUN_80006c88();
extern void* FUN_80006c9c();
extern undefined4 FUN_8001741c();
extern undefined8 FUN_80017484();
extern undefined4 FUN_80053754();
extern undefined4 FUN_8005398c();
extern undefined4 FUN_800709e8();
extern undefined4 FUN_80286830();
extern undefined4 FUN_8028687c();

extern undefined4 DAT_8031ce04;
extern undefined4 DAT_8031ce0a;
extern undefined2 DAT_803aa0b8;
extern undefined DAT_803b0000;
extern undefined4 DAT_803de330;
extern undefined4 DAT_803de57a;
extern undefined4 DAT_803de57c;
extern undefined4 DAT_803de57e;
extern undefined4 DAT_803de580;
extern undefined4 DAT_803de582;
extern undefined4 DAT_803de584;
extern undefined4 DAT_803de58c;
extern undefined4 DAT_803de58e;
extern undefined4 DAT_803de591;
extern undefined4 DAT_803de592;
extern f64 DOUBLE_803e2e70;

/*
 * --INFO--
 *
 * Function: FUN_80130888
 * EN v1.0 Address: 0x80130888
 * EN v1.0 Size: 368b
 * EN v1.1 Address: 0x801309A8
 * EN v1.1 Size: 616b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80130888(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  undefined4 uVar1;
  undefined *puVar2;
  undefined *extraout_r4;
  int iVar3;
  undefined2 *puVar4;
  
  puVar2 = &DAT_803b0000;
  puVar4 = &DAT_803aa0b8;
  for (iVar3 = 0; iVar3 < DAT_803de591; iVar3 = iVar3 + 1) {
    puVar4[0xb] = *(undefined2 *)(param_9 + 0x16);
    *(undefined *)(puVar4 + 0xd) = *(undefined *)(param_9 + 0x1a);
    puVar4[2] = *(undefined2 *)(param_9 + 4);
    if (*(int *)(param_9 + 0x10) == -1) {
      if (*(int *)(puVar4 + 8) != 0) {
        param_1 = FUN_80053754();
        puVar2 = extraout_r4;
      }
      *(undefined4 *)(puVar4 + 8) = 0;
    }
    else if (*(int *)(puVar4 + 8) == 0) {
      uVar1 = FUN_8005398c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                           *(int *)(param_9 + 0x10),puVar2,param_11,param_12,param_13,param_14,
                           param_15,param_16);
      *(undefined4 *)(puVar4 + 8) = uVar1;
    }
    puVar4 = puVar4 + 0x1e;
    param_9 = param_9 + 0x3c;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801309f8
 * EN v1.0 Address: 0x801309F8
 * EN v1.0 Size: 1312b
 * EN v1.1 Address: 0x80130C10
 * EN v1.1 Size: 1128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801309f8(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  char cVar1;
  ushort uVar2;
  byte bVar4;
  int iVar3;
  undefined *puVar5;
  ushort *puVar6;
  uint uVar7;
  int iVar8;
  int iVar9;
  ushort *puVar10;
  undefined8 uVar11;
  double dVar12;
  
  FUN_80286830();
  puVar10 = &DAT_803aa0b8;
  for (iVar9 = 0; iVar9 < DAT_803de591; iVar9 = iVar9 + 1) {
    if ((puVar10[0xb] & 0x4000) == 0) {
      if ((puVar10[0xb] & 0x1040) == 0) {
        puVar6 = puVar10;
        if (*(char *)(puVar10 + 0xf) != -1) {
          puVar6 = &DAT_803aa0b8 + *(char *)(puVar10 + 0xf) * 0x1e;
        }
        if ((puVar6[0xb] & 4) != 0) {
          iVar8 = 0;
          uVar7 = (uint)(short)puVar6[5];
          uVar2 = puVar6[6];
          dVar12 = DOUBLE_803e2e70;
          while( true ) {
            cVar1 = *(char *)((int)puVar6 + iVar8 + 0x1f);
            if ((cVar1 == -1) || (0x18 < iVar8)) break;
            param_2 = (double)(float)((double)CONCAT44(0x43300000,(int)(short)uVar2 ^ 0x80000000) -
                                     dVar12);
            FUN_800709e8((double)(float)((double)CONCAT44(0x43300000,uVar7 ^ 0x80000000) - dVar12),
                         param_2,(&DAT_8031ce04)[cVar1 * 2],0xff,0x100);
            uVar7 = uVar7 + (byte)(&DAT_8031ce0a)[*(char *)((int)puVar6 + iVar8 + 0x1f) * 8];
            iVar8 = iVar8 + 1;
          }
        }
        if ((puVar6[0xb] & 0x800) == 0) {
          iVar8 = (int)DAT_803de58c;
        }
        else {
          iVar8 = DAT_803de58c * 200 >> 8;
        }
        FUN_8001741c((uint)puVar6[1]);
        iVar3 = iVar8;
        if (DAT_803de592 != iVar9) {
          iVar3 = iVar8 / 2;
        }
        puVar5 = FUN_80006c9c((uint)puVar6[1]);
        puVar5[0x1e] = (char)iVar3;
        if ((puVar6[0xb] & 0x100) != 0) {
          uVar11 = FUN_80017484(0,0,0,(byte)((uint)((DAT_803de58e + 1) * (int)DAT_803de58c) >> 8));
          FUN_80006c84(uVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(uint)*puVar6,
                       2,2);
        }
        if ((puVar6[0xb] & 0x80) == 0) {
          uVar11 = FUN_80017484(0xff,0xff,0xff,(byte)iVar8);
        }
        else if (DAT_803de592 == iVar9) {
          iVar8 = (int)DAT_803de58e;
          if ((puVar6[0xb] & 0x800) == 0) {
            bVar4 = (byte)DAT_803de58c;
          }
          else {
            bVar4 = (byte)((uint)(DAT_803de58c * 200) >> 8);
          }
          uVar11 = FUN_80017484((byte)DAT_803de584 +
                                (char)((uint)(iVar8 * ((int)DAT_803de57e - (int)DAT_803de584)) >> 8)
                                ,(byte)DAT_803de582 +
                                 (char)((uint)(iVar8 * ((int)DAT_803de57c - (int)DAT_803de582)) >> 8
                                       ),(byte)DAT_803de580 +
                                         (char)((uint)(iVar8 * ((int)DAT_803de57a -
                                                               (int)DAT_803de580)) >> 8),bVar4);
        }
        else {
          uVar11 = FUN_80017484((byte)DAT_803de584,(byte)DAT_803de582,(byte)DAT_803de580,
                                (byte)(iVar8 / 2));
        }
        uVar7 = (uint)*puVar6;
        if ((uVar7 < 0x15) || (uVar7 == 0xffff)) {
          if (uVar7 != 0xffff) {
            FUN_80006c64(DAT_803de330 + uVar7 * 0x24,(uint)puVar6[1],0,0);
          }
        }
        else {
          FUN_80006c88(uVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar7);
        }
        iVar8 = *(int *)(puVar6 + 8);
        if (iVar8 != 0) {
          uVar2 = puVar6[0xb];
          if ((uVar2 & 4) == 0) {
            param_2 = (double)(float)((double)CONCAT44(0x43300000,(int)(short)puVar6[6] ^ 0x80000000
                                                      ) - DOUBLE_803e2e70);
            if ((uVar2 & 0x800) == 0) {
              uVar7 = (uint)DAT_803de58c;
            }
            else {
              uVar7 = DAT_803de58c * 200 >> 8;
            }
            FUN_800709e8((double)(float)((double)CONCAT44(0x43300000,
                                                          (int)(short)puVar6[5] ^ 0x80000000) -
                                        DOUBLE_803e2e70),param_2,iVar8,uVar7 & 0xff,0x100);
          }
          else {
            param_2 = (double)(float)((double)CONCAT44(0x43300000,(int)(short)puVar6[6] ^ 0x80000000
                                                      ) - DOUBLE_803e2e70);
            if ((uVar2 & 0x800) == 0) {
              uVar7 = (uint)DAT_803de58c;
            }
            else {
              uVar7 = DAT_803de58c * 200 >> 8;
            }
            FUN_800709e8((double)(float)((double)CONCAT44(0x43300000,
                                                          (int)(short)puVar6[5] + 0xbU ^ 0x80000000)
                                        - DOUBLE_803e2e70),param_2,iVar8,uVar7 & 0xff,0x100);
          }
        }
        cVar1 = *(char *)(puVar6 + 0x1c);
        *(char *)(puVar6 + 0x1c) = cVar1 + -1;
        if ((char)(cVar1 + -1) < '\0') {
          *(undefined *)(puVar6 + 0x1c) = 0;
        }
      }
      else {
        cVar1 = *(char *)(puVar10 + 0x1c);
        *(char *)(puVar10 + 0x1c) = cVar1 + -1;
        if ((char)(cVar1 + -1) < '\0') {
          *(undefined *)(puVar10 + 0x1c) = 0;
        }
      }
    }
    puVar10 = puVar10 + 0x1e;
  }
  FUN_8001741c(0xff);
  FUN_8028687c();
  return;
}
