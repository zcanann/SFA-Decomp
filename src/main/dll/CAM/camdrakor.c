#include "ghidra_import.h"
#include "main/dll/CAM/camdrakor.h"
#include "main/dll/CAM/dll_60.h"

extern undefined4 Obj_TransformWorldPointToLocal();
extern void* FUN_800069a8();
extern uint getButtonsJustPressed();
extern double FUN_800176f4();
extern uint getAngle();
extern undefined4 FUN_80017814();
extern undefined4 FUN_80017830();
extern undefined4 FUN_80053bb0();
extern void *mmAlloc(int size,int heap,int flags);
extern undefined4 camcontrol_traceMove();
extern uint FUN_801ef1a4();
extern undefined4 FUN_80247e94();
extern undefined4 FUN_80247eb8();
extern undefined4 FUN_80247edc();
extern undefined4 FUN_80247ef8();
extern double FUN_80247f54();
extern undefined4 Camera_GetCurrentViewSlot();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_80293130();
extern double sqrtf();
extern undefined4 fn_80293E80();
extern undefined4 sin();
extern uint FUN_80294c90();
extern int FUN_80294c98();
extern undefined4 fn_80296BD4();

extern undefined4* lbl_803DCA50;
extern f32* lbl_803DD568;
extern s32 lbl_803DD56C;
extern f32* lbl_803DD570;
extern void* lbl_803DD578;
extern f64 lbl_803E1918;
extern f64 lbl_803E1938;
extern f64 lbl_803E1988;
extern f32 timeDelta;
extern f32 lbl_803E18C0;
extern f32 lbl_803E18C4;
extern f32 lbl_803E18CC;
extern f32 lbl_803E18D0;
extern f32 lbl_803E18D4;
extern f32 lbl_803E18D8;
extern f32 lbl_803E18DC;
extern f32 lbl_803E18E0;
extern f32 lbl_803E18E4;
extern f32 lbl_803E18E8;
extern f32 lbl_803E18EC;
extern f32 lbl_803E18F0;
extern f32 lbl_803E18F4;
extern f32 lbl_803E18F8;
extern f32 lbl_803E1904;
extern f32 lbl_803E1908;
extern f32 lbl_803E190C;
extern f32 lbl_803E1910;
extern f32 lbl_803E1920;
extern f32 lbl_803E1924;
extern f32 lbl_803E1928;
extern f32 lbl_803E192C;
extern f32 lbl_803E1930;
extern f32 lbl_803E1940;
extern f32 lbl_803E1948;
extern f32 lbl_803E194C;
extern f32 lbl_803E1950;
extern f32 lbl_803E1954;
extern f32 lbl_803E1958;
extern f32 lbl_803E195C;
extern f32 lbl_803E1960;
extern f32 lbl_803E1964;
extern f32 lbl_803E1968;
extern f32 lbl_803E196C;
extern f32 lbl_803E1970;
extern f32 lbl_803E1974;
extern f32 lbl_803E1978;
extern f32 lbl_803E197C;
extern f32 lbl_803E1980;

/*
 * --INFO--
 *
 * Function: CameraModeCombat_update
 * EN v1.0 Address: 0x8010C0D8
 * EN v1.0 Size: 3352b
 * EN v1.1 Address: 0x8010C374
 * EN v1.1 Size: 3204b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void CameraModeCombat_update(void)
{
  float fVar1;
  short sVar2;
  float fVar3;
  short *psVar4;
  undefined2 *puVar5;
  int iVar6;
  uint uVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  double dVar11;
  double dVar12;
  double in_f27;
  double dVar13;
  double in_f28;
  double dVar14;
  double in_f29;
  double dVar15;
  double in_f30;
  double dVar16;
  double in_f31;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  float local_128;
  float local_124;
  float local_120;
  float local_11c;
  float fStack_118;
  undefined4 uStack_114;
  undefined4 uStack_110;
  float local_10c;
  float local_108;
  float local_104;
  float afStack_100 [3];
  undefined auStack_f4 [116];
  undefined8 local_80;
  undefined4 local_78;
  uint uStack_74;
  undefined8 local_70;
  float local_48;
  float fStack_44;
  float local_38;
  float fStack_34;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  local_48 = (float)in_f27;
  fStack_44 = (float)in_ps27_1;
  psVar4 = (short *)Camera_GetCurrentViewSlot();
  puVar5 = FUN_800069a8();
  if (*(char *)((int)lbl_803DD568 + 0x12) == '\0') {
    iVar8 = *(int *)(psVar4 + 0x52);
    if ((*(short *)(iVar8 + 0x44) == 1) && (iVar6 = FUN_80294c98(iVar8), iVar6 == 0)) {
      if (*(int *)(psVar4 + 0x8e) != 0) {
        if (((*(byte *)(*(int *)(psVar4 + 0x8e) + 0xaf) & 0x40) != 0) ||
           ((*(byte *)((int)psVar4 + 0x141) & 2) != 0)) goto LAB_8010cfb8;
        (**(code **)(*lbl_803DCA50 + 0x48))(0);
      }
      (**(code **)(*lbl_803DCA50 + 0x1c))(0x42,0,1,0,0,0x1e,0xff);
    }
    else {
      iVar6 = *(int *)(psVar4 + 0x8e);
      if ((iVar6 == 0) ||
         (((*(ushort *)(iVar6 + 0xb0) & 0x40) != 0 || ((*(byte *)(iVar6 + 0xaf) & 0x28) != 0)))) {
        if (iVar6 != 0) {
          if (((*(byte *)(iVar6 + 0xaf) & 0x40) != 0) || ((*(byte *)((int)psVar4 + 0x141) & 2) != 0)
             ) goto LAB_8010cfb8;
          (**(code **)(*lbl_803DCA50 + 0x48))(0);
        }
        (**(code **)(*lbl_803DCA50 + 0x1c))(0x42,0,1,0,0,0x1e,0xff);
      }
      else {
        iVar9 = *(int *)(iVar6 + 0x74);
        if (iVar9 != 0) {
          local_80 = (double)CONCAT44(0x43300000,
                                      (uint)*(byte *)(*(int *)(*(int *)(iVar6 + 0x50) + 0x40) + 0xd)
                                      << 2 ^ 0x80000000);
          dVar14 = (double)(float)(local_80 - lbl_803E1938);
          uVar7 = getButtonsJustPressed(0);
          if (((uVar7 & 0x200) == 0) || (uVar7 = FUN_80294c90(iVar8), uVar7 == 0)) {
            local_120 = lbl_803E18D0 + *(float *)(iVar8 + 0x1c);
            sVar2 = *(short *)(iVar6 + 0x44);
            if ((sVar2 == 0x1c) || ((sVar2 == 0x6d || (sVar2 == 0x2a)))) {
              if (*(short *)(iVar6 + 0x46) == 0x200) {
                local_120 = local_120 + lbl_803E18D0;
              }
              if (*(byte *)(*(int *)(iVar6 + 0x50) + 0x72) < 2) {
                local_124 = *(float *)(iVar9 + (uint)*(byte *)(iVar6 + 0xe4) * 0x18 + 0xc) -
                            *(float *)(iVar8 + 0x18);
                local_11c = *(float *)(iVar9 + (uint)*(byte *)(iVar6 + 0xe4) * 0x18 + 0x10) -
                            local_120;
                local_128 = *(float *)(iVar9 + (uint)*(byte *)(iVar6 + 0xe4) * 0x18 + 0x14) -
                            *(float *)(iVar8 + 0x20);
              }
              else {
                camdrakor_computeTargetOffset
                          ((int)psVar4,&local_124,&local_11c,&local_128,&local_120);
              }
            }
            else {
              local_120 = lbl_803E18D0 + *(float *)(iVar8 + 0x1c);
              local_124 = *(float *)(iVar9 + (uint)*(byte *)(iVar6 + 0xe4) * 0x18 + 0xc) -
                          *(float *)(iVar8 + 0x18);
              local_11c = *(float *)(iVar9 + (uint)*(byte *)(iVar6 + 0xe4) * 0x18 + 0x10) -
                          local_120;
              local_128 = *(float *)(iVar9 + (uint)*(byte *)(iVar6 + 0xe4) * 0x18 + 0x14) -
                          *(float *)(iVar8 + 0x20);
            }
            dVar11 = sqrtf((double)(local_124 * local_124 + local_128 * local_128));
            *(undefined *)((int)psVar4 + 0x13b) = 0x30;
            *(undefined *)(psVar4 + 0x9e) = 1;
            if (dVar11 <= dVar14) {
              fn_80296BD4(iVar8,&fStack_118,&uStack_114,&uStack_110);
              dVar16 = (double)(lbl_803E18D4 * local_124 + *(float *)(iVar8 + 0x18));
              dVar15 = (double)(lbl_803E18D8 + local_120);
              dVar14 = (double)(lbl_803E18D4 * local_128 + *(float *)(iVar8 + 0x20));
              uVar7 = getAngle();
              iVar9 = (int)*psVar4 - (0x8000 - ((uVar7 & 0xffff) + 0x8000) & 0xffff);
              if (0x8000 < iVar9) {
                iVar9 = iVar9 + -0xffff;
              }
              if (iVar9 < -0x8000) {
                iVar9 = iVar9 + 0xffff;
              }
              if (iVar9 < 0x2329) {
                if (iVar9 < -9000) {
                  local_70 = (double)CONCAT44(0x43300000,iVar9 + 9000U ^ 0x80000000);
                  dVar12 = FUN_800176f4((double)(float)(local_70 - lbl_803E1938),
                                        (double)lbl_803E18DC,(double)timeDelta);
                  uStack_74 = (int)*psVar4 ^ 0x80000000;
                  local_78 = 0x43300000;
                  iVar10 = (int)((double)(float)((double)CONCAT44(0x43300000,uStack_74) -
                                                lbl_803E1938) - dVar12);
                  local_80 = (double)(longlong)iVar10;
                  *psVar4 = (short)iVar10;
                }
              }
              else {
                local_80 = (double)CONCAT44(0x43300000,iVar9 - 9000U ^ 0x80000000);
                dVar12 = FUN_800176f4((double)(float)(local_80 - lbl_803E1938),
                                      (double)lbl_803E18DC,(double)timeDelta);
                uStack_74 = (int)*psVar4 ^ 0x80000000;
                local_78 = 0x43300000;
                *psVar4 = (short)(int)((double)(float)((double)CONCAT44(0x43300000,uStack_74) -
                                                      lbl_803E1938) - dVar12);
              }
              if ((iVar9 < 3000) && (0 < iVar9)) {
                if (((lbl_803DD56C < 3000) && (iVar9 < 1000)) && (iVar9 < lbl_803DD56C)) {
                  local_70 = (double)CONCAT44(0x43300000,-iVar9 - 3000U ^ 0x80000000);
                  dVar12 = FUN_800176f4((double)(float)(local_70 - lbl_803E1938),
                                        (double)lbl_803E18E0,(double)timeDelta);
                  uStack_74 = (int)*psVar4 ^ 0x80000000;
                  local_78 = 0x43300000;
                  iVar10 = (int)((double)(float)((double)CONCAT44(0x43300000,uStack_74) -
                                                lbl_803E1938) + dVar12);
                  local_80 = (double)(longlong)iVar10;
                  *psVar4 = (short)iVar10;
                }
                else {
                  local_70 = (double)CONCAT44(0x43300000,3000U - iVar9 ^ 0x80000000);
                  dVar12 = FUN_800176f4((double)(float)(local_70 - lbl_803E1938),
                                        (double)lbl_803E18E0,(double)timeDelta);
                  uStack_74 = (int)*psVar4 ^ 0x80000000;
                  local_78 = 0x43300000;
                  iVar10 = (int)((double)(float)((double)CONCAT44(0x43300000,uStack_74) -
                                                lbl_803E1938) + dVar12);
                  local_80 = (double)(longlong)iVar10;
                  *psVar4 = (short)iVar10;
                }
              }
              else if ((-3000 < iVar9) && (iVar9 < 0)) {
                if (((lbl_803DD56C < -2999) || (iVar9 < -999)) || (iVar9 <= lbl_803DD56C)) {
                  local_70 = (double)CONCAT44(0x43300000,-iVar9 - 3000U ^ 0x80000000);
                  dVar12 = FUN_800176f4((double)(float)(local_70 - lbl_803E1938),
                                        (double)lbl_803E18E0,(double)timeDelta);
                  uStack_74 = (int)*psVar4 ^ 0x80000000;
                  local_78 = 0x43300000;
                  iVar10 = (int)((double)(float)((double)CONCAT44(0x43300000,uStack_74) -
                                                lbl_803E1938) + dVar12);
                  local_80 = (double)(longlong)iVar10;
                  *psVar4 = (short)iVar10;
                }
                else {
                  local_70 = (double)CONCAT44(0x43300000,3000U - iVar9 ^ 0x80000000);
                  dVar12 = FUN_800176f4((double)(float)(local_70 - lbl_803E1938),
                                        (double)lbl_803E18E0,(double)timeDelta);
                  uStack_74 = (int)*psVar4 ^ 0x80000000;
                  local_78 = 0x43300000;
                  iVar10 = (int)((double)(float)((double)CONCAT44(0x43300000,uStack_74) -
                                                lbl_803E1938) + dVar12);
                  local_80 = (double)(longlong)iVar10;
                  *psVar4 = (short)iVar10;
                }
              }
              iVar10 = iVar9;
              if (iVar9 < 0) {
                iVar10 = -iVar9;
              }
              if (9000 < iVar10) {
                iVar10 = 9000;
              }
              local_70 = (double)CONCAT44(0x43300000,9000U - iVar10 ^ 0x80000000);
              dVar13 = (double)((float)(local_70 - lbl_803E1938) / lbl_803E18E4);
              lbl_803DD56C = iVar9;
              dVar12 = FUN_800176f4((double)(lbl_803E18E8 - lbl_803DD568[1]),
                                    (double)lbl_803E18EC,(double)timeDelta);
              lbl_803DD568[1] = (float)((double)lbl_803DD568[1] + dVar12);
              dVar12 = FUN_800176f4((double)((lbl_803E18F0 +
                                             (float)((double)lbl_803E18C0 - dVar13)) /
                                             lbl_803E18F4 - lbl_803DD568[2]),
                                    (double)lbl_803E18F8,(double)timeDelta);
              lbl_803DD568[2] = (float)((double)lbl_803DD568[2] + dVar12);
              uStack_74 = (int)*psVar4 ^ 0x80000000;
              local_78 = 0x43300000;
              dVar12 = (double)fn_80293E80();
              local_80 = (double)CONCAT44(0x43300000,(int)*psVar4 ^ 0x80000000);
              dVar13 = (double)sin();
              local_10c = (float)(dVar16 + (double)(float)((double)*lbl_803DD568 * dVar12));
              local_104 = (float)(dVar14 - (double)(float)((double)*lbl_803DD568 * dVar13));
              local_11c = (local_120 - local_11c * lbl_803E1904) + lbl_803DD568[1];
              dVar14 = FUN_800176f4((double)(*(float *)(psVar4 + 0xe) - local_11c),
                                    (double)lbl_803E1908,(double)timeDelta);
              local_108 = (float)((double)*(float *)(psVar4 + 0xe) - dVar14);
              FUN_80247eb8(&local_10c,(float *)(psVar4 + 0xc),afStack_100);
              dVar14 = FUN_80247f54(afStack_100);
              if ((double)lbl_803E18C4 < dVar14) {
                FUN_80247ef8(afStack_100,afStack_100);
              }
              dVar16 = dVar14;
              if (*(float *)(psVar4 + 0x7a) <= lbl_803E18C4) {
                fVar1 = *(float *)(iVar8 + 0x8c) - *(float *)(iVar8 + 0x18);
                fVar3 = *(float *)(iVar8 + 0x94) - *(float *)(iVar8 + 0x20);
                dVar16 = sqrtf((double)(fVar1 * fVar1 + fVar3 * fVar3));
                dVar12 = (double)(float)(dVar16 * (double)(lbl_803E190C * timeDelta));
                if (dVar12 < lbl_803E1918) {
                  dVar12 = (double)lbl_803E1910;
                }
                dVar16 = (double)lbl_803E18C4;
                if ((dVar16 <= dVar14) && (dVar16 = dVar14, dVar12 < dVar14)) {
                  dVar16 = dVar12;
                }
              }
              dVar14 = (double)lbl_803E18C4;
              if ((dVar14 <= dVar16) && (dVar14 = dVar16, (double)lbl_803E18D0 < dVar16)) {
                dVar14 = (double)lbl_803E18D0;
              }
              FUN_80247edc(dVar14,afStack_100,afStack_100);
              FUN_80247e94((float *)(psVar4 + 0xc),afStack_100,(float *)(psVar4 + 0xc));
              camcontrol_traceMove((double)lbl_803E18CC,&fStack_118,(float *)(psVar4 + 0xc),
                                   (float *)(psVar4 + 0xc),(int)auStack_f4,3,'\x01','\x01');
              fVar3 = *(float *)(puVar5 + 6) -
                      (lbl_803E18F8 * local_124 + *(float *)(iVar8 + 0x18));
              local_11c = (float)((double)*(float *)(puVar5 + 8) - dVar15);
              fVar1 = *(float *)(puVar5 + 10) -
                      (lbl_803E18F8 * local_128 + *(float *)(iVar8 + 0x20));
              sqrtf((double)(fVar3 * fVar3 + fVar1 * fVar1));
              uVar7 = getAngle();
              uVar7 = (uVar7 & 0xffff) - (uint)(ushort)psVar4[1];
              if (0x8000 < (int)uVar7) {
                uVar7 = uVar7 - 0xffff;
              }
              if ((int)uVar7 < -0x8000) {
                uVar7 = uVar7 + 0xffff;
              }
              local_70 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              dVar14 = FUN_800176f4((double)(float)(local_70 - lbl_803E1938),
                                    (double)lbl_803E1920,(double)timeDelta);
              uStack_74 = (int)psVar4[1] ^ 0x80000000;
              local_78 = 0x43300000;
              iVar8 = (int)((double)(float)((double)CONCAT44(0x43300000,uStack_74) - lbl_803E1938
                                           ) + dVar14);
              local_80 = (double)(longlong)iVar8;
              psVar4[1] = (short)iVar8;
              fVar1 = (float)((double)lbl_803E1924 + dVar11);
              if ((float)((double)lbl_803E1924 + dVar11) < lbl_803E1928) {
                fVar1 = lbl_803E1928;
              }
              if (lbl_803E192C < fVar1) {
                fVar1 = lbl_803E192C;
              }
              dVar11 = (double)(fVar1 - *lbl_803DD568);
              dVar14 = (double)FUN_80293130((double)lbl_803E18EC,(double)timeDelta);
              fVar1 = (float)(dVar11 * dVar14);
              fVar3 = lbl_803E18D8 * timeDelta;
              if ((fVar1 <= fVar3) && (fVar3 = fVar1, fVar1 < lbl_803E1930 * timeDelta)) {
                fVar3 = lbl_803E1930 * timeDelta;
              }
              *lbl_803DD568 = *lbl_803DD568 + fVar3;
              FUN_80053bb0((double)*(float *)(iVar6 + 0x18),(double)*(float *)(iVar6 + 0x1c),
                           (double)*(float *)(iVar6 + 0x20),1,0);
              if (lbl_803E18C4 == *(float *)(psVar4 + 0x7a)) {
                *(byte *)((int)psVar4 + 0x143) = *(byte *)((int)psVar4 + 0x143) & 0x7f | 0x80;
              }
              Obj_TransformWorldPointToLocal((double)*(float *)(psVar4 + 0xc),(double)*(float *)(psVar4 + 0xe),
                           (double)*(float *)(psVar4 + 0x10),(float *)(psVar4 + 6),
                           (float *)(psVar4 + 8),(float *)(psVar4 + 10),*(int *)(psVar4 + 0x18));
            }
            else {
              if (*(int *)(psVar4 + 0x8e) != 0) {
                if (((*(byte *)(*(int *)(psVar4 + 0x8e) + 0xaf) & 0x40) != 0) ||
                   ((*(byte *)((int)psVar4 + 0x141) & 2) != 0)) goto LAB_8010cfb8;
                (**(code **)(*lbl_803DCA50 + 0x48))(0);
              }
              (**(code **)(*lbl_803DCA50 + 0x1c))(0x42,0,1,0,0,0x1e,0xff);
            }
          }
          else {
            if (*(int *)(psVar4 + 0x8e) != 0) {
              if (((*(byte *)(*(int *)(psVar4 + 0x8e) + 0xaf) & 0x40) != 0) ||
                 ((*(byte *)((int)psVar4 + 0x141) & 2) != 0)) goto LAB_8010cfb8;
              (**(code **)(*lbl_803DCA50 + 0x48))(0);
            }
            (**(code **)(*lbl_803DCA50 + 0x1c))(0x42,0,1,0,0,0x1e,0xff);
          }
        }
      }
    }
  }
  else {
    if (*(int *)(psVar4 + 0x8e) != 0) {
      if (((*(byte *)(*(int *)(psVar4 + 0x8e) + 0xaf) & 0x40) != 0) ||
         ((*(byte *)((int)psVar4 + 0x141) & 2) != 0)) goto LAB_8010cfb8;
      (**(code **)(*lbl_803DCA50 + 0x48))(0);
    }
    (**(code **)(*lbl_803DCA50 + 0x1c))(0x42,0,1,0,0,0x1e,0xff);
  }
LAB_8010cfb8:
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: CameraModeCombat_init
 * EN v1.0 Address: 0x8010CDF0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8010CFF8
 * EN v1.1 Size: 360b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void CameraModeCombat_init(int param_1,undefined4 param_2,undefined4 *param_3)
{
  float fVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  double dVar6;

  *(undefined4 *)(param_1 + 0x11c) = *param_3;
  iVar5 = *(int *)(param_1 + 0xa4);
  if (lbl_803DD568 == (float *)0x0) {
    lbl_803DD568 = (float *)mmAlloc(0x1c,0xf,0);
  }
  fVar1 = lbl_803E18C4;
  lbl_803DD568[1] = lbl_803E18C4;
  lbl_803DD568[2] = lbl_803E18C0;
  *(undefined *)((int)lbl_803DD568 + 0x12) = 0;
  *(undefined *)((int)lbl_803DD568 + 0x11) = 0;
  *(undefined *)((int)lbl_803DD568 + 0x13) = 1;
  *(undefined *)(lbl_803DD568 + 5) = 1;
  lbl_803DD568[6] = fVar1;
  if (*(short *)(iVar5 + 0x44) == 1) {
    iVar4 = *(int *)(param_1 + 0x11c);
    if (iVar4 == 0) {
      *(undefined *)((int)lbl_803DD568 + 0x12) = 1;
    }
    else {
      if (*(int *)(iVar4 + 0x74) == 0) {
        fVar1 = *(float *)(iVar5 + 0x18) - *(float *)(iVar4 + 0x18);
        fVar2 = *(float *)(iVar5 + 0x20) - *(float *)(iVar4 + 0x20);
      }
      else {
        iVar3 = *(int *)(iVar4 + 0x74) + (uint)*(byte *)(iVar4 + 0xe4) * 0x18;
        fVar1 = *(float *)(iVar3 + 0xc) - *(float *)(iVar5 + 0x18);
        fVar2 = *(float *)(iVar3 + 0x14) - *(float *)(iVar5 + 0x20);
      }
      if (*(short *)(iVar4 + 0x44) == 0x6d) {
        *lbl_803DD568 = lbl_803E1940;
      }
      else {
        dVar6 = (double)sqrtf((double)(fVar1 * fVar1 + fVar2 * fVar2));
        *lbl_803DD568 = (float)dVar6;
      }
      *(undefined *)(lbl_803DD568 + 4) = 0;
    }
  }
  else {
    *(undefined *)((int)lbl_803DD568 + 0x12) = 1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8010cdf4
 * EN v1.0 Address: 0x8010CDF4
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x8010D160
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8010cdf4(void)
{
  FUN_80017814(lbl_803DD570);
  lbl_803DD570 = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: CameraModeShipBattle_update
 * EN v1.0 Address: 0x8010CE20
 * EN v1.0 Size: 1580b
 * EN v1.1 Address: 0x8010D18C
 * EN v1.1 Size: 936b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void CameraModeShipBattle_update(undefined2 *param_1)
{
  float fVar1;
  float fVar2;
  float fVar3;
  double dVar4;
  uint uVar5;
  int iVar6;
  
  uVar5 = 0;
  iVar6 = *(int *)(param_1 + 0x52);
  if (iVar6 != 0) {
    uVar5 = FUN_801ef1a4(iVar6);
  }
  if (uVar5 != *(byte *)(lbl_803DD570 + 10)) {
    fVar3 = lbl_803E1948;
    if ((uVar5 == 2) ||
       (fVar1 = lbl_803E1950, fVar2 = lbl_803E1954, fVar3 = lbl_803E194C, uVar5 == 5)) {
      fVar1 = lbl_803E1958;
      fVar2 = lbl_803DD570[1];
    }
    *(char *)(lbl_803DD570 + 10) = (char)uVar5;
    lbl_803DD570[6] = fVar3 - lbl_803DD570[3];
    lbl_803DD570[4] = lbl_803DD570[3];
    lbl_803DD570[9] = fVar1 - (lbl_803DD570[7] + fVar2);
    lbl_803DD570[8] = lbl_803DD570[7];
    lbl_803DD570[5] = lbl_803E1954;
  }
  fVar3 = lbl_803E195C;
  if (lbl_803DD570[5] < lbl_803E195C) {
    lbl_803DD570[5] = lbl_803E1960 * timeDelta + lbl_803DD570[5];
    if (fVar3 < lbl_803DD570[5]) {
      lbl_803DD570[5] = fVar3;
    }
    lbl_803DD570[3] = lbl_803DD570[5] * lbl_803DD570[6] + lbl_803DD570[4];
    lbl_803DD570[7] = lbl_803DD570[5] * lbl_803DD570[9] + lbl_803DD570[8];
  }
  dVar4 = lbl_803E1988;
  if ((uVar5 == 2) || (uVar5 == 5)) {
    *lbl_803DD570 =
         -(((float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar6 + 4) ^ 0x80000000) -
                   lbl_803E1988) / lbl_803E1964) * timeDelta - *lbl_803DD570);
    lbl_803DD570[1] =
         -(((float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar6 + 2) ^ 0x80000000) - dVar4) /
           lbl_803E1968) * timeDelta - lbl_803DD570[1]);
    fVar3 = lbl_803E196C;
    *lbl_803DD570 = -(lbl_803E196C * *lbl_803DD570 * timeDelta - *lbl_803DD570);
    lbl_803DD570[1] = -(fVar3 * lbl_803DD570[1] * timeDelta - lbl_803DD570[1]);
    *(float *)(param_1 + 0xe) = lbl_803DD570[1] + *(float *)(iVar6 + 0x1c) + lbl_803DD570[7];
  }
  else {
    *lbl_803DD570 =
         -(((float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar6 + 4) ^ 0x80000000) -
                   lbl_803E1988) / lbl_803E1964) * timeDelta - *lbl_803DD570);
    lbl_803DD570[1] =
         -(((float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar6 + 2) ^ 0x80000000) - dVar4) /
           lbl_803E1968) * timeDelta - lbl_803DD570[1]);
    fVar3 = lbl_803E196C;
    *lbl_803DD570 = -(lbl_803E196C * *lbl_803DD570 * timeDelta - *lbl_803DD570);
    lbl_803DD570[1] = -(fVar3 * lbl_803DD570[1] * timeDelta - lbl_803DD570[1]);
    *(float *)(param_1 + 0xe) = lbl_803DD570[1] + *(float *)(iVar6 + 0x1c) + lbl_803DD570[7];
  }
  *(float *)(param_1 + 0xc) = lbl_803E1970 + *(float *)(iVar6 + 0x18) + lbl_803DD570[2];
  *(float *)(param_1 + 0x10) = *(float *)(iVar6 + 0x20) + *lbl_803DD570;
  param_1[1] = 0x708;
  *param_1 = 0x4000;
  param_1[2] = (short)(-(int)*(short *)(iVar6 + 4) >> 3);
  *(float *)(param_1 + 0x5a) = lbl_803E1974;
  fVar3 = (lbl_803DD570[3] - lbl_803DD570[2]) / lbl_803E1978;
  fVar1 = lbl_803E197C;
  if ((fVar3 <= lbl_803E197C) && (fVar1 = fVar3, fVar3 < lbl_803E1980)) {
    fVar1 = lbl_803E1980;
  }
  lbl_803DD570[2] = lbl_803DD570[2] + fVar1 * timeDelta;
  Obj_TransformWorldPointToLocal((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0xe),
               (double)*(float *)(param_1 + 0x10),(float *)(param_1 + 6),(float *)(param_1 + 8),
               (float *)(param_1 + 10),*(int *)(param_1 + 0x18));
  return;
}

/*
 * --INFO--
 *
 * Function: CameraModeShipBattle_init
 * EN v1.0 Address: 0x8010D44C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8010D534
 * EN v1.1 Size: 168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void CameraModeShipBattle_init(void)
{
  float fVar1;

  if (lbl_803DD570 == (float *)0x0) {
    lbl_803DD570 = (float *)mmAlloc(0x2c,0xf,0);
  }
  fVar1 = lbl_803E1954;
  *lbl_803DD570 = lbl_803E1954;
  lbl_803DD570[1] = fVar1;
  lbl_803DD570[2] = lbl_803E1978;
  fVar1 = lbl_803E194C;
  lbl_803DD570[4] = lbl_803E194C;
  lbl_803DD570[3] = fVar1;
  lbl_803DD570[5] = lbl_803E195C;
  *(undefined *)(lbl_803DD570 + 10) = 0;
  fVar1 = lbl_803E1950;
  lbl_803DD570[8] = lbl_803E1950;
  lbl_803DD570[7] = fVar1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8010d450
 * EN v1.0 Address: 0x8010D450
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x8010D5DC
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8010d450(void)
{
  FUN_80017814(lbl_803DD578);
  lbl_803DD578 = 0;
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void CameraModeCombat_release(void) {}
void CameraModeCombat_initialise(void) {}
void CameraModeShipBattle_func06_nop(void) {}
void CameraModeShipBattle_release(void) {}
void CameraModeShipBattle_initialise(void) {}
void CameraModeClimb_func06_nop(void) {}

/* fn_X(lbl); lbl = 0; */
extern void mm_free(void *);
#pragma scheduling off
#pragma peephole off
void CameraModeShipBattle_free(void) { mm_free(lbl_803DD570); lbl_803DD570 = 0; }
void CameraModeClimb_func05(void) { mm_free(lbl_803DD578); lbl_803DD578 = 0; }
#pragma peephole reset
#pragma scheduling reset
