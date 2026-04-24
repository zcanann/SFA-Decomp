#include "ghidra_import.h"
#include "main/dll/CAM/camdrakor.h"

extern undefined4 FUN_8000e054();
extern void* FUN_8000facc();
extern uint FUN_80014e9c();
extern double FUN_80021434();
extern uint FUN_80021884();
extern undefined4 FUN_800238c4();
extern undefined4 FUN_80023d8c();
extern undefined4 FUN_800551f8();
extern undefined4 camcontrol_traceMove();
extern undefined4 FUN_8010c1a4();
extern uint FUN_801ef35c();
extern undefined4 FUN_80247e94();
extern undefined4 FUN_80247eb8();
extern undefined4 FUN_80247edc();
extern undefined4 FUN_80247ef8();
extern double FUN_80247f54();
extern undefined4 FUN_80286840();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_802932a4();
extern double FUN_80293900();
extern undefined4 FUN_802945e0();
extern undefined4 FUN_80294964();
extern uint FUN_80296a6c();
extern int FUN_80296a88();
extern undefined4 FUN_80297334();

extern undefined4* DAT_803dd6d0;
extern undefined4* DAT_803de1e0;
extern undefined4 DAT_803de1e4;
extern undefined4* DAT_803de1e8;
extern undefined4 DAT_803de1f0;
extern f64 DOUBLE_803e2598;
extern f64 DOUBLE_803e25b8;
extern f64 DOUBLE_803e2608;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e2540;
extern f32 FLOAT_803e2544;
extern f32 FLOAT_803e254c;
extern f32 FLOAT_803e2550;
extern f32 FLOAT_803e2554;
extern f32 FLOAT_803e2558;
extern f32 FLOAT_803e255c;
extern f32 FLOAT_803e2560;
extern f32 FLOAT_803e2564;
extern f32 FLOAT_803e2568;
extern f32 FLOAT_803e256c;
extern f32 FLOAT_803e2570;
extern f32 FLOAT_803e2574;
extern f32 FLOAT_803e2578;
extern f32 FLOAT_803e2584;
extern f32 FLOAT_803e2588;
extern f32 FLOAT_803e258c;
extern f32 FLOAT_803e2590;
extern f32 FLOAT_803e25a0;
extern f32 FLOAT_803e25a4;
extern f32 FLOAT_803e25a8;
extern f32 FLOAT_803e25ac;
extern f32 FLOAT_803e25b0;
extern f32 FLOAT_803e25c0;
extern f32 FLOAT_803e25c8;
extern f32 FLOAT_803e25cc;
extern f32 FLOAT_803e25d0;
extern f32 FLOAT_803e25d4;
extern f32 FLOAT_803e25d8;
extern f32 FLOAT_803e25dc;
extern f32 FLOAT_803e25e0;
extern f32 FLOAT_803e25e4;
extern f32 FLOAT_803e25e8;
extern f32 FLOAT_803e25ec;
extern f32 FLOAT_803e25f0;
extern f32 FLOAT_803e25f4;
extern f32 FLOAT_803e25f8;
extern f32 FLOAT_803e25fc;
extern f32 FLOAT_803e2600;

/*
 * --INFO--
 *
 * Function: FUN_8010c374
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x8010C374
 * EN v1.1 Size: 3204b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8010c374(void)
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
  psVar4 = (short *)FUN_80286840();
  puVar5 = FUN_8000facc();
  if (*(char *)((int)DAT_803de1e0 + 0x12) == '\0') {
    iVar8 = *(int *)(psVar4 + 0x52);
    if ((*(short *)(iVar8 + 0x44) == 1) && (iVar6 = FUN_80296a88(iVar8), iVar6 == 0)) {
      if (*(int *)(psVar4 + 0x8e) != 0) {
        if (((*(byte *)(*(int *)(psVar4 + 0x8e) + 0xaf) & 0x40) != 0) ||
           ((*(byte *)((int)psVar4 + 0x141) & 2) != 0)) goto LAB_8010cfb8;
        (**(code **)(*DAT_803dd6d0 + 0x48))(0);
      }
      (**(code **)(*DAT_803dd6d0 + 0x1c))(0x42,0,1,0,0,0x1e,0xff);
    }
    else {
      iVar6 = *(int *)(psVar4 + 0x8e);
      if ((iVar6 == 0) ||
         (((*(ushort *)(iVar6 + 0xb0) & 0x40) != 0 || ((*(byte *)(iVar6 + 0xaf) & 0x28) != 0)))) {
        if (iVar6 != 0) {
          if (((*(byte *)(iVar6 + 0xaf) & 0x40) != 0) || ((*(byte *)((int)psVar4 + 0x141) & 2) != 0)
             ) goto LAB_8010cfb8;
          (**(code **)(*DAT_803dd6d0 + 0x48))(0);
        }
        (**(code **)(*DAT_803dd6d0 + 0x1c))(0x42,0,1,0,0,0x1e,0xff);
      }
      else {
        iVar9 = *(int *)(iVar6 + 0x74);
        if (iVar9 != 0) {
          local_80 = (double)CONCAT44(0x43300000,
                                      (uint)*(byte *)(*(int *)(*(int *)(iVar6 + 0x50) + 0x40) + 0xd)
                                      << 2 ^ 0x80000000);
          dVar14 = (double)(float)(local_80 - DOUBLE_803e25b8);
          uVar7 = FUN_80014e9c(0);
          if (((uVar7 & 0x200) == 0) || (uVar7 = FUN_80296a6c(iVar8), uVar7 == 0)) {
            local_120 = FLOAT_803e2550 + *(float *)(iVar8 + 0x1c);
            sVar2 = *(short *)(iVar6 + 0x44);
            if ((sVar2 == 0x1c) || ((sVar2 == 0x6d || (sVar2 == 0x2a)))) {
              if (*(short *)(iVar6 + 0x46) == 0x200) {
                local_120 = local_120 + FLOAT_803e2550;
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
                FUN_8010c1a4((int)psVar4,&local_124,&local_11c,&local_128,&local_120);
              }
            }
            else {
              local_120 = FLOAT_803e2550 + *(float *)(iVar8 + 0x1c);
              local_124 = *(float *)(iVar9 + (uint)*(byte *)(iVar6 + 0xe4) * 0x18 + 0xc) -
                          *(float *)(iVar8 + 0x18);
              local_11c = *(float *)(iVar9 + (uint)*(byte *)(iVar6 + 0xe4) * 0x18 + 0x10) -
                          local_120;
              local_128 = *(float *)(iVar9 + (uint)*(byte *)(iVar6 + 0xe4) * 0x18 + 0x14) -
                          *(float *)(iVar8 + 0x20);
            }
            dVar11 = FUN_80293900((double)(local_124 * local_124 + local_128 * local_128));
            *(undefined *)((int)psVar4 + 0x13b) = 0x30;
            *(undefined *)(psVar4 + 0x9e) = 1;
            if (dVar11 <= dVar14) {
              FUN_80297334(iVar8,&fStack_118,&uStack_114,&uStack_110);
              dVar16 = (double)(FLOAT_803e2554 * local_124 + *(float *)(iVar8 + 0x18));
              dVar15 = (double)(FLOAT_803e2558 + local_120);
              dVar14 = (double)(FLOAT_803e2554 * local_128 + *(float *)(iVar8 + 0x20));
              uVar7 = FUN_80021884();
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
                  dVar12 = FUN_80021434((double)(float)(local_70 - DOUBLE_803e25b8),
                                        (double)FLOAT_803e255c,(double)FLOAT_803dc074);
                  uStack_74 = (int)*psVar4 ^ 0x80000000;
                  local_78 = 0x43300000;
                  iVar10 = (int)((double)(float)((double)CONCAT44(0x43300000,uStack_74) -
                                                DOUBLE_803e25b8) - dVar12);
                  local_80 = (double)(longlong)iVar10;
                  *psVar4 = (short)iVar10;
                }
              }
              else {
                local_80 = (double)CONCAT44(0x43300000,iVar9 - 9000U ^ 0x80000000);
                dVar12 = FUN_80021434((double)(float)(local_80 - DOUBLE_803e25b8),
                                      (double)FLOAT_803e255c,(double)FLOAT_803dc074);
                uStack_74 = (int)*psVar4 ^ 0x80000000;
                local_78 = 0x43300000;
                *psVar4 = (short)(int)((double)(float)((double)CONCAT44(0x43300000,uStack_74) -
                                                      DOUBLE_803e25b8) - dVar12);
              }
              if ((iVar9 < 3000) && (0 < iVar9)) {
                if (((DAT_803de1e4 < 3000) && (iVar9 < 1000)) && (iVar9 < DAT_803de1e4)) {
                  local_70 = (double)CONCAT44(0x43300000,-iVar9 - 3000U ^ 0x80000000);
                  dVar12 = FUN_80021434((double)(float)(local_70 - DOUBLE_803e25b8),
                                        (double)FLOAT_803e2560,(double)FLOAT_803dc074);
                  uStack_74 = (int)*psVar4 ^ 0x80000000;
                  local_78 = 0x43300000;
                  iVar10 = (int)((double)(float)((double)CONCAT44(0x43300000,uStack_74) -
                                                DOUBLE_803e25b8) + dVar12);
                  local_80 = (double)(longlong)iVar10;
                  *psVar4 = (short)iVar10;
                }
                else {
                  local_70 = (double)CONCAT44(0x43300000,3000U - iVar9 ^ 0x80000000);
                  dVar12 = FUN_80021434((double)(float)(local_70 - DOUBLE_803e25b8),
                                        (double)FLOAT_803e2560,(double)FLOAT_803dc074);
                  uStack_74 = (int)*psVar4 ^ 0x80000000;
                  local_78 = 0x43300000;
                  iVar10 = (int)((double)(float)((double)CONCAT44(0x43300000,uStack_74) -
                                                DOUBLE_803e25b8) + dVar12);
                  local_80 = (double)(longlong)iVar10;
                  *psVar4 = (short)iVar10;
                }
              }
              else if ((-3000 < iVar9) && (iVar9 < 0)) {
                if (((DAT_803de1e4 < -2999) || (iVar9 < -999)) || (iVar9 <= DAT_803de1e4)) {
                  local_70 = (double)CONCAT44(0x43300000,-iVar9 - 3000U ^ 0x80000000);
                  dVar12 = FUN_80021434((double)(float)(local_70 - DOUBLE_803e25b8),
                                        (double)FLOAT_803e2560,(double)FLOAT_803dc074);
                  uStack_74 = (int)*psVar4 ^ 0x80000000;
                  local_78 = 0x43300000;
                  iVar10 = (int)((double)(float)((double)CONCAT44(0x43300000,uStack_74) -
                                                DOUBLE_803e25b8) + dVar12);
                  local_80 = (double)(longlong)iVar10;
                  *psVar4 = (short)iVar10;
                }
                else {
                  local_70 = (double)CONCAT44(0x43300000,3000U - iVar9 ^ 0x80000000);
                  dVar12 = FUN_80021434((double)(float)(local_70 - DOUBLE_803e25b8),
                                        (double)FLOAT_803e2560,(double)FLOAT_803dc074);
                  uStack_74 = (int)*psVar4 ^ 0x80000000;
                  local_78 = 0x43300000;
                  iVar10 = (int)((double)(float)((double)CONCAT44(0x43300000,uStack_74) -
                                                DOUBLE_803e25b8) + dVar12);
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
              dVar13 = (double)((float)(local_70 - DOUBLE_803e25b8) / FLOAT_803e2564);
              DAT_803de1e4 = iVar9;
              dVar12 = FUN_80021434((double)(FLOAT_803e2568 - DAT_803de1e0[1]),
                                    (double)FLOAT_803e256c,(double)FLOAT_803dc074);
              DAT_803de1e0[1] = (float)((double)DAT_803de1e0[1] + dVar12);
              dVar12 = FUN_80021434((double)((FLOAT_803e2570 +
                                             (float)((double)FLOAT_803e2540 - dVar13)) /
                                             FLOAT_803e2574 - DAT_803de1e0[2]),
                                    (double)FLOAT_803e2578,(double)FLOAT_803dc074);
              DAT_803de1e0[2] = (float)((double)DAT_803de1e0[2] + dVar12);
              uStack_74 = (int)*psVar4 ^ 0x80000000;
              local_78 = 0x43300000;
              dVar12 = (double)FUN_802945e0();
              local_80 = (double)CONCAT44(0x43300000,(int)*psVar4 ^ 0x80000000);
              dVar13 = (double)FUN_80294964();
              local_10c = (float)(dVar16 + (double)(float)((double)*DAT_803de1e0 * dVar12));
              local_104 = (float)(dVar14 - (double)(float)((double)*DAT_803de1e0 * dVar13));
              local_11c = (local_120 - local_11c * FLOAT_803e2584) + DAT_803de1e0[1];
              dVar14 = FUN_80021434((double)(*(float *)(psVar4 + 0xe) - local_11c),
                                    (double)FLOAT_803e2588,(double)FLOAT_803dc074);
              local_108 = (float)((double)*(float *)(psVar4 + 0xe) - dVar14);
              FUN_80247eb8(&local_10c,(float *)(psVar4 + 0xc),afStack_100);
              dVar14 = FUN_80247f54(afStack_100);
              if ((double)FLOAT_803e2544 < dVar14) {
                FUN_80247ef8(afStack_100,afStack_100);
              }
              dVar16 = dVar14;
              if (*(float *)(psVar4 + 0x7a) <= FLOAT_803e2544) {
                fVar1 = *(float *)(iVar8 + 0x8c) - *(float *)(iVar8 + 0x18);
                fVar3 = *(float *)(iVar8 + 0x94) - *(float *)(iVar8 + 0x20);
                dVar16 = FUN_80293900((double)(fVar1 * fVar1 + fVar3 * fVar3));
                dVar12 = (double)(float)(dVar16 * (double)(FLOAT_803e258c * FLOAT_803dc074));
                if (dVar12 < DOUBLE_803e2598) {
                  dVar12 = (double)FLOAT_803e2590;
                }
                dVar16 = (double)FLOAT_803e2544;
                if ((dVar16 <= dVar14) && (dVar16 = dVar14, dVar12 < dVar14)) {
                  dVar16 = dVar12;
                }
              }
              dVar14 = (double)FLOAT_803e2544;
              if ((dVar14 <= dVar16) && (dVar14 = dVar16, (double)FLOAT_803e2550 < dVar16)) {
                dVar14 = (double)FLOAT_803e2550;
              }
              FUN_80247edc(dVar14,afStack_100,afStack_100);
              FUN_80247e94((float *)(psVar4 + 0xc),afStack_100,(float *)(psVar4 + 0xc));
              camcontrol_traceMove((double)FLOAT_803e254c,&fStack_118,(float *)(psVar4 + 0xc),
                                   (float *)(psVar4 + 0xc),(int)auStack_f4,3,'\x01','\x01');
              fVar3 = *(float *)(puVar5 + 6) -
                      (FLOAT_803e2578 * local_124 + *(float *)(iVar8 + 0x18));
              local_11c = (float)((double)*(float *)(puVar5 + 8) - dVar15);
              fVar1 = *(float *)(puVar5 + 10) -
                      (FLOAT_803e2578 * local_128 + *(float *)(iVar8 + 0x20));
              FUN_80293900((double)(fVar3 * fVar3 + fVar1 * fVar1));
              uVar7 = FUN_80021884();
              uVar7 = (uVar7 & 0xffff) - (uint)(ushort)psVar4[1];
              if (0x8000 < (int)uVar7) {
                uVar7 = uVar7 - 0xffff;
              }
              if ((int)uVar7 < -0x8000) {
                uVar7 = uVar7 + 0xffff;
              }
              local_70 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
              dVar14 = FUN_80021434((double)(float)(local_70 - DOUBLE_803e25b8),
                                    (double)FLOAT_803e25a0,(double)FLOAT_803dc074);
              uStack_74 = (int)psVar4[1] ^ 0x80000000;
              local_78 = 0x43300000;
              iVar8 = (int)((double)(float)((double)CONCAT44(0x43300000,uStack_74) - DOUBLE_803e25b8
                                           ) + dVar14);
              local_80 = (double)(longlong)iVar8;
              psVar4[1] = (short)iVar8;
              fVar1 = (float)((double)FLOAT_803e25a4 + dVar11);
              if ((float)((double)FLOAT_803e25a4 + dVar11) < FLOAT_803e25a8) {
                fVar1 = FLOAT_803e25a8;
              }
              if (FLOAT_803e25ac < fVar1) {
                fVar1 = FLOAT_803e25ac;
              }
              dVar11 = (double)(fVar1 - *DAT_803de1e0);
              dVar14 = (double)FUN_802932a4((double)FLOAT_803e256c,(double)FLOAT_803dc074);
              fVar1 = (float)(dVar11 * dVar14);
              fVar3 = FLOAT_803e2558 * FLOAT_803dc074;
              if ((fVar1 <= fVar3) && (fVar3 = fVar1, fVar1 < FLOAT_803e25b0 * FLOAT_803dc074)) {
                fVar3 = FLOAT_803e25b0 * FLOAT_803dc074;
              }
              *DAT_803de1e0 = *DAT_803de1e0 + fVar3;
              FUN_800551f8((double)*(float *)(iVar6 + 0x18),(double)*(float *)(iVar6 + 0x1c),
                           (double)*(float *)(iVar6 + 0x20),1,0);
              if (FLOAT_803e2544 == *(float *)(psVar4 + 0x7a)) {
                *(byte *)((int)psVar4 + 0x143) = *(byte *)((int)psVar4 + 0x143) & 0x7f | 0x80;
              }
              FUN_8000e054((double)*(float *)(psVar4 + 0xc),(double)*(float *)(psVar4 + 0xe),
                           (double)*(float *)(psVar4 + 0x10),(float *)(psVar4 + 6),
                           (float *)(psVar4 + 8),(float *)(psVar4 + 10),*(int *)(psVar4 + 0x18));
            }
            else {
              if (*(int *)(psVar4 + 0x8e) != 0) {
                if (((*(byte *)(*(int *)(psVar4 + 0x8e) + 0xaf) & 0x40) != 0) ||
                   ((*(byte *)((int)psVar4 + 0x141) & 2) != 0)) goto LAB_8010cfb8;
                (**(code **)(*DAT_803dd6d0 + 0x48))(0);
              }
              (**(code **)(*DAT_803dd6d0 + 0x1c))(0x42,0,1,0,0,0x1e,0xff);
            }
          }
          else {
            if (*(int *)(psVar4 + 0x8e) != 0) {
              if (((*(byte *)(*(int *)(psVar4 + 0x8e) + 0xaf) & 0x40) != 0) ||
                 ((*(byte *)((int)psVar4 + 0x141) & 2) != 0)) goto LAB_8010cfb8;
              (**(code **)(*DAT_803dd6d0 + 0x48))(0);
            }
            (**(code **)(*DAT_803dd6d0 + 0x1c))(0x42,0,1,0,0,0x1e,0xff);
          }
        }
      }
    }
  }
  else {
    if (*(int *)(psVar4 + 0x8e) != 0) {
      if (((*(byte *)(*(int *)(psVar4 + 0x8e) + 0xaf) & 0x40) != 0) ||
         ((*(byte *)((int)psVar4 + 0x141) & 2) != 0)) goto LAB_8010cfb8;
      (**(code **)(*DAT_803dd6d0 + 0x48))(0);
    }
    (**(code **)(*DAT_803dd6d0 + 0x1c))(0x42,0,1,0,0,0x1e,0xff);
  }
LAB_8010cfb8:
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8010cff8
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x8010CFF8
 * EN v1.1 Size: 360b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8010cff8(int param_1,undefined4 param_2,undefined4 *param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8010d160
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x8010D160
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8010d160(void)
{
  FUN_800238c4(DAT_803de1e8);
  DAT_803de1e8 = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8010d18c
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x8010D18C
 * EN v1.1 Size: 936b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8010d18c(undefined2 *param_1)
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
    uVar5 = FUN_801ef35c(iVar6);
  }
  if (uVar5 != *(byte *)(DAT_803de1e8 + 10)) {
    fVar3 = FLOAT_803e25c8;
    if ((uVar5 == 2) ||
       (fVar1 = FLOAT_803e25d0, fVar2 = FLOAT_803e25d4, fVar3 = FLOAT_803e25cc, uVar5 == 5)) {
      fVar1 = FLOAT_803e25d8;
      fVar2 = DAT_803de1e8[1];
    }
    *(char *)(DAT_803de1e8 + 10) = (char)uVar5;
    DAT_803de1e8[6] = fVar3 - DAT_803de1e8[3];
    DAT_803de1e8[4] = DAT_803de1e8[3];
    DAT_803de1e8[9] = fVar1 - (DAT_803de1e8[7] + fVar2);
    DAT_803de1e8[8] = DAT_803de1e8[7];
    DAT_803de1e8[5] = FLOAT_803e25d4;
  }
  fVar3 = FLOAT_803e25dc;
  if (DAT_803de1e8[5] < FLOAT_803e25dc) {
    DAT_803de1e8[5] = FLOAT_803e25e0 * FLOAT_803dc074 + DAT_803de1e8[5];
    if (fVar3 < DAT_803de1e8[5]) {
      DAT_803de1e8[5] = fVar3;
    }
    DAT_803de1e8[3] = DAT_803de1e8[5] * DAT_803de1e8[6] + DAT_803de1e8[4];
    DAT_803de1e8[7] = DAT_803de1e8[5] * DAT_803de1e8[9] + DAT_803de1e8[8];
  }
  dVar4 = DOUBLE_803e2608;
  if ((uVar5 == 2) || (uVar5 == 5)) {
    *DAT_803de1e8 =
         -(((float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar6 + 4) ^ 0x80000000) -
                   DOUBLE_803e2608) / FLOAT_803e25e4) * FLOAT_803dc074 - *DAT_803de1e8);
    DAT_803de1e8[1] =
         -(((float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar6 + 2) ^ 0x80000000) - dVar4) /
           FLOAT_803e25e8) * FLOAT_803dc074 - DAT_803de1e8[1]);
    fVar3 = FLOAT_803e25ec;
    *DAT_803de1e8 = -(FLOAT_803e25ec * *DAT_803de1e8 * FLOAT_803dc074 - *DAT_803de1e8);
    DAT_803de1e8[1] = -(fVar3 * DAT_803de1e8[1] * FLOAT_803dc074 - DAT_803de1e8[1]);
    *(float *)(param_1 + 0xe) = DAT_803de1e8[1] + *(float *)(iVar6 + 0x1c) + DAT_803de1e8[7];
  }
  else {
    *DAT_803de1e8 =
         -(((float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar6 + 4) ^ 0x80000000) -
                   DOUBLE_803e2608) / FLOAT_803e25e4) * FLOAT_803dc074 - *DAT_803de1e8);
    DAT_803de1e8[1] =
         -(((float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar6 + 2) ^ 0x80000000) - dVar4) /
           FLOAT_803e25e8) * FLOAT_803dc074 - DAT_803de1e8[1]);
    fVar3 = FLOAT_803e25ec;
    *DAT_803de1e8 = -(FLOAT_803e25ec * *DAT_803de1e8 * FLOAT_803dc074 - *DAT_803de1e8);
    DAT_803de1e8[1] = -(fVar3 * DAT_803de1e8[1] * FLOAT_803dc074 - DAT_803de1e8[1]);
    *(float *)(param_1 + 0xe) = DAT_803de1e8[1] + *(float *)(iVar6 + 0x1c) + DAT_803de1e8[7];
  }
  *(float *)(param_1 + 0xc) = FLOAT_803e25f0 + *(float *)(iVar6 + 0x18) + DAT_803de1e8[2];
  *(float *)(param_1 + 0x10) = *(float *)(iVar6 + 0x20) + *DAT_803de1e8;
  param_1[1] = 0x708;
  *param_1 = 0x4000;
  param_1[2] = (short)(-(int)*(short *)(iVar6 + 4) >> 3);
  *(float *)(param_1 + 0x5a) = FLOAT_803e25f4;
  fVar3 = (DAT_803de1e8[3] - DAT_803de1e8[2]) / FLOAT_803e25f8;
  fVar1 = FLOAT_803e25fc;
  if ((fVar3 <= FLOAT_803e25fc) && (fVar1 = fVar3, fVar3 < FLOAT_803e2600)) {
    fVar1 = FLOAT_803e2600;
  }
  DAT_803de1e8[2] = DAT_803de1e8[2] + fVar1 * FLOAT_803dc074;
  FUN_8000e054((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0xe),
               (double)*(float *)(param_1 + 0x10),(float *)(param_1 + 6),(float *)(param_1 + 8),
               (float *)(param_1 + 10),*(int *)(param_1 + 0x18));
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8010d534
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x8010D534
 * EN v1.1 Size: 168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8010d534(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8010d5dc
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x8010D5DC
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8010d5dc(void)
{
  FUN_800238c4(DAT_803de1f0);
  DAT_803de1f0 = 0;
  return;
}
