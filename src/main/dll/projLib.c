#include "ghidra_import.h"
#include "main/dll/projLib.h"

extern undefined4 FUN_8001771c();
extern uint FUN_80017760();
extern undefined4 FUN_80017a98();
extern int ObjGroup_FindNearestObject();
extern int Obj_GetYawDeltaToObject();
extern undefined4 FUN_80038bb0();
extern void* FUN_80039518();
extern undefined4 FUN_8003a420();
extern undefined4 FUN_8003a8ac();
extern undefined4 FUN_8003a9c8();
extern undefined4 FUN_8003ac24();
extern undefined4 FUN_8003ad08();
extern undefined8 FUN_80286840();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern uint countLeadingZeros();

extern undefined4 DAT_803dc070;
extern f32 lbl_803E290C;
extern f32 lbl_803E2910;
extern f32 lbl_803E2924;
extern f32 lbl_803E2950;
extern f32 lbl_803E2954;
extern f32 lbl_803E2958;

/*
 * --INFO--
 *
 * Function: dll_2E_func03
 * EN v1.0 Address: 0x80115094
 * EN v1.0 Size: 16b
 * EN v1.1 Address: 0x80115318
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_2E_func03(int param_1,undefined4 param_2,undefined4 param_3)
{
  *(undefined4 *)(param_1 + 0x618) = param_2;
  *(undefined4 *)(param_1 + 0x61c) = param_3;
  *(undefined4 *)(param_1 + 0x620) = param_2;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801150a4
 * EN v1.0 Address: 0x801150A4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80115328
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801150a4(int param_1,undefined4 param_2)
{
  *(undefined4 *)(param_1 + 0x608) = param_2;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801150ac
 * EN v1.0 Address: 0x801150AC
 * EN v1.0 Size: 1260b
 * EN v1.1 Address: 0x80115330
 * EN v1.1 Size: 1468b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801150ac(void)
{
  float fVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  ushort *puVar5;
  uint *puVar6;
  uint *puVar7;
  undefined4 uVar8;
  int iVar9;
  int iVar10;
  short sVar11;
  double dVar12;
  double in_f31;
  double in_ps31_1;
  undefined8 uVar13;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  undefined4 local_38;
  uint uStack_34;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar13 = FUN_80286840();
  puVar5 = (ushort *)((ulonglong)uVar13 >> 0x20);
  iVar10 = (int)uVar13;
  local_48 = lbl_803E290C;
  sVar11 = 0;
  puVar6 = FUN_80039518();
  FUN_80017a98();
  if (*(char *)(iVar10 + 0x601) == '\0') {
    if (((*(byte *)(iVar10 + 0x611) & 1) == 0) || (*(char *)(iVar10 + 0x600) == '\b')) {
      if (((*(byte *)(iVar10 + 0x611) & 1) == 0) &&
         ((*(char *)(iVar10 + 0x600) == '\b' &&
          (*(undefined *)(iVar10 + 0x600) = 0, (*(byte *)(iVar10 + 0x611) & 8) == 0)))) {
        FUN_8003ad08((int)puVar5,puVar6,(uint)*(byte *)(iVar10 + 0x610),iVar10 + 0x1c);
        *(undefined4 *)(iVar10 + 0x5f8) = 0x50;
      }
    }
    else {
      *(undefined *)(iVar10 + 0x600) = 8;
      if ((*(byte *)(iVar10 + 0x611) & 8) == 0) {
        FUN_8003ad08((int)puVar5,puVar6,(uint)*(byte *)(iVar10 + 0x610),iVar10 + 0x1c);
        *(undefined4 *)(iVar10 + 0x5f8) = 0x50;
        FUN_8003a9c8(iVar10 + 0x1c,(uint)*(byte *)(iVar10 + 0x610),0,0);
      }
      else {
        puVar7 = FUN_80039518();
        FUN_8003ac24((int)puVar5,puVar7,(uint)*(byte *)(iVar10 + 0x610));
      }
    }
    if (*(byte *)(iVar10 + 0x600) < 2) {
      iVar9 = *(int *)(iVar10 + 0x608);
      if (iVar9 == 0) {
        iVar9 = ObjGroup_FindNearestObject(8,puVar5,&local_48);
      }
      if (iVar9 != 0) {
        if ((*(byte *)(iVar10 + 0x611) & 0x20) != 0) {
          local_44 = *(float *)(iVar10 + 0x10) - *(float *)(iVar9 + 0xc);
          local_40 = *(float *)(iVar10 + 0x14) - *(float *)(iVar9 + 0x10);
          local_3c = *(float *)(iVar10 + 0x18) - *(float *)(iVar9 + 0x14);
          dVar12 = FUN_80293900((double)(local_44 * local_44 + local_3c * local_3c));
          if (dVar12 <= (double)lbl_803E2954) {
            fVar1 = (float)(dVar12 - (double)lbl_803E2958) / lbl_803E2950;
            fVar2 = lbl_803E2910;
            if ((lbl_803E2910 <= fVar1) && (fVar2 = fVar1, lbl_803E2924 < fVar1)) {
              fVar2 = lbl_803E2924;
            }
            fVar2 = lbl_803E2924 - fVar2;
            fVar1 = lbl_803E2924 - fVar2;
            *(float *)(iVar10 + 0x10) =
                 *(float *)(iVar10 + 0x10) * fVar1 + *(float *)(puVar5 + 6) * fVar2;
            *(float *)(iVar10 + 0x18) =
                 *(float *)(iVar10 + 0x18) * fVar1 + *(float *)(puVar5 + 10) * fVar2;
          }
        }
        if ((*(int *)(iVar10 + 0x618) == -1) || (iVar9 != *(int *)(iVar10 + 0x604))) {
          *(int *)(iVar10 + 0x620) = *(int *)(iVar10 + 0x618);
        }
        else {
          iVar4 = *(int *)(iVar10 + 0x620) - (uint)DAT_803dc070;
          *(int *)(iVar10 + 0x620) = iVar4;
          if ((iVar4 < 1) && (0 < (int)(*(int *)(iVar10 + 0x620) + (uint)DAT_803dc070))) {
            FUN_8003ad08((int)puVar5,puVar6,(uint)*(byte *)(iVar10 + 0x610),iVar10 + 0x1c);
            *(undefined4 *)(iVar10 + 0x5f8) = 0x50;
            FUN_8003a9c8(iVar10 + 0x1c,(uint)*(byte *)(iVar10 + 0x610),0,0);
            *(undefined *)(iVar10 + 0x600) = 0;
            goto LAB_801158cc;
          }
          if (*(int *)(iVar10 + 0x5f8) != 0) {
            uVar8 = FUN_8003a8ac(puVar5,puVar6,(uint)*(byte *)(iVar10 + 0x610),iVar10 + 0x1c);
            uVar3 = countLeadingZeros(uVar8);
            *(uint *)(iVar10 + 0x5f8) = uVar3 >> 5;
          }
          if (*(int *)(iVar10 + 0x620) < (int)-*(uint *)(iVar10 + 0x61c)) {
            uVar3 = FUN_80017760(*(uint *)(iVar10 + 0x61c),*(uint *)(iVar10 + 0x618));
            *(uint *)(iVar10 + 0x620) = uVar3;
          }
          if (*(int *)(iVar10 + 0x620) < 0) goto LAB_801158cc;
        }
        if (((iVar9 != *(int *)(iVar10 + 0x604)) && (iVar9 != 0)) &&
           (iVar4 = *(int *)(iVar9 + 0x54), iVar4 != 0)) {
          if ((*(byte *)(iVar4 + 0x62) & 2) == 0) {
            if ((*(byte *)(iVar4 + 0x62) & 1) != 0) {
              uStack_34 = (int)*(short *)(iVar4 + 0x5a) ^ 0x80000000;
              local_38 = 0x43300000;
            }
          }
          else {
            uStack_34 = (int)*(short *)(iVar4 + 0x5e) ^ 0x80000000;
            local_38 = 0x43300000;
          }
        }
        if (iVar9 != 0) {
          iVar4 = Obj_GetYawDeltaToObject(puVar5,iVar9,(float *)0x0);
          sVar11 = (short)iVar4;
        }
        if ((*(byte *)(iVar10 + 0x611) & 0x10) != 0) {
          FUN_80038bb0('\0',1);
          sVar11 = sVar11 + -0x8000;
        }
        iVar4 = (int)sVar11;
        if (iVar4 < 0) {
          iVar4 = -iVar4;
        }
        if (((0x5555 < iVar4) || (iVar9 == 0)) ||
           (dVar12 = (double)FUN_8001771c((float *)(puVar5 + 0xc),(float *)(iVar9 + 0x18)),
           (double)*(float *)(iVar10 + 0x614) < dVar12)) {
          if ((*(char *)(iVar10 + 0x600) != '\0') ||
             ((iVar9 == 0 && (*(int *)(iVar10 + 0x604) != 0)))) {
            FUN_8003ad08((int)puVar5,puVar6,(uint)*(byte *)(iVar10 + 0x610),iVar10 + 0x1c);
            *(undefined4 *)(iVar10 + 0x5f8) = 10;
            FUN_8003a9c8(iVar10 + 0x1c,(uint)*(byte *)(iVar10 + 0x610),0,0);
            *(undefined *)(iVar10 + 0x600) = 0;
          }
        }
        else {
          if ((iVar9 != *(int *)(iVar10 + 0x604)) || (*(char *)(iVar10 + 0x600) == '\0')) {
            FUN_8003ad08((int)puVar5,puVar6,(uint)*(byte *)(iVar10 + 0x610),iVar10 + 0x1c);
            *(undefined4 *)(iVar10 + 0x5f8) = 1;
          }
          if ((*(byte *)(iVar10 + 0x611) & 8) != 0) {
            *(undefined4 *)(iVar10 + 0x5f8) = 0;
          }
          if (*(int *)(iVar10 + 0x5f8) == 0) {
            iVar4 = 0;
          }
          else {
            iVar4 = iVar10 + 0x1c;
          }
          FUN_8003a420(puVar5,iVar9,(float *)(iVar10 + 0x10),iVar4,(short *)(iVar10 + 0x5bc),8,
                       *(short *)(iVar10 + 0x60c));
          *(undefined *)(iVar10 + 0x600) = 1;
        }
        *(int *)(iVar10 + 0x604) = iVar9;
        if (*(int *)(iVar10 + 0x5f8) == 0) {
          *(undefined4 *)(iVar10 + 0x608) = 0;
        }
        if (((*(byte *)(iVar10 + 0x611) & 8) == 0) && (*(int *)(iVar10 + 0x5f8) != 0)) {
          uVar8 = FUN_8003a8ac(puVar5,puVar6,(uint)*(byte *)(iVar10 + 0x610),iVar10 + 0x1c);
          uVar3 = countLeadingZeros(uVar8);
          *(uint *)(iVar10 + 0x5f8) = uVar3 >> 5;
        }
      }
    }
    else if ((*(int *)(iVar10 + 0x5f8) == 0) || ((*(byte *)(iVar10 + 0x611) & 8) != 0)) {
      puVar6 = FUN_80039518();
      FUN_8003ac24((int)puVar5,puVar6,(uint)*(byte *)(iVar10 + 0x610));
    }
    else {
      uVar8 = FUN_8003a8ac(puVar5,puVar6,(uint)*(byte *)(iVar10 + 0x610),iVar10 + 0x1c);
      uVar3 = countLeadingZeros(uVar8);
      *(uint *)(iVar10 + 0x5f8) = uVar3 >> 5;
    }
  }
LAB_801158cc:
  FUN_8028688c();
  return;
}
