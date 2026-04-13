// Function: FUN_801a87d4
// Entry: 801a87d4
// Size: 1736 bytes

/* WARNING: Removing unreachable block (ram,0x801a8e7c) */
/* WARNING: Removing unreachable block (ram,0x801a87e4) */

void FUN_801a87d4(void)

{
  float fVar1;
  ushort uVar2;
  bool bVar3;
  float fVar4;
  float fVar5;
  int *piVar6;
  int iVar7;
  char cVar10;
  uint uVar8;
  undefined4 *puVar9;
  int *piVar11;
  int iVar12;
  int iVar13;
  undefined8 uVar14;
  double dVar15;
  double dVar16;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  double in_f31;
  double in_ps31_1;
  int local_58;
  int local_54;
  undefined8 local_50;
  longlong local_48;
  undefined4 local_40;
  uint uStack_3c;
  longlong local_38;
  longlong local_30;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  piVar6 = (int *)FUN_80286840();
  iVar13 = piVar6[0x2e];
  iVar12 = piVar6[0x13];
  dVar16 = (double)(float)piVar6[5];
  iVar7 = FUN_8005b478((double)(float)piVar6[3],(double)(float)piVar6[4]);
  fVar1 = FLOAT_803e51ec;
  if ((iVar7 != -1) && ((*(ushort *)(iVar13 + 0x24) & 4) == 0)) {
    if ((*(ushort *)(iVar13 + 0x24) & 0x200) == 0) {
      FUN_80097568((double)FLOAT_803e5214,(double)FLOAT_803e51e4,piVar6,1,5,1,10,0,0);
      dVar15 = (double)FLOAT_803e51e4;
      FUN_80097568((double)FLOAT_803e5214,dVar15,piVar6,5,5,1,0x14,0,0);
      if ((*(ushort *)(iVar13 + 0x24) & 0x40) == 0) {
        bVar3 = false;
        if (((*(ushort *)(iVar13 + 0x24) & 8) == 0) ||
           (cVar10 = (**(code **)(*DAT_803dd72c + 0x4c))(0x12,6), cVar10 != '\0')) {
          if ((*(ushort *)(iVar13 + 0x24) & 0x400) == 0) {
            if (((int)*(short *)(iVar12 + 0x20) == 0xffffffff) ||
               (uVar8 = FUN_80020078((int)*(short *)(iVar12 + 0x20)), uVar8 != 0)) {
              iVar7 = (**(code **)(*DAT_803dd740 + 8))(piVar6,piVar6[0x2e]);
              if (iVar7 != 0) {
                bVar3 = true;
              }
            }
            else {
              *(byte *)((int)piVar6 + 0xaf) = *(byte *)((int)piVar6 + 0xaf) | 8;
            }
          }
          else {
            *(byte *)((int)piVar6 + 0xaf) = *(byte *)((int)piVar6 + 0xaf) | 8;
          }
        }
        else {
          *(ushort *)(iVar13 + 0x24) = *(ushort *)(iVar13 + 0x24) | 1;
        }
        *(ushort *)(iVar13 + 0x24) = *(ushort *)(iVar13 + 0x24) & 0xfff7;
        if (bVar3) {
          iVar7 = FUN_8002bac4();
          uVar8 = FUN_802979fc(iVar7);
          if ((uVar8 & 0x4000) == 0) {
            FUN_8011f6d0(4);
            *(ushort *)(iVar13 + 0x24) = *(ushort *)(iVar13 + 0x24) | 0x28;
            *(ushort *)(iVar13 + 0x24) = *(ushort *)(iVar13 + 0x24) & 0xffef;
          }
          else {
            FUN_8011f6d0(5);
            *(ushort *)(iVar13 + 0x24) = *(ushort *)(iVar13 + 0x24) | 0x18;
            *(ushort *)(iVar13 + 0x24) = *(ushort *)(iVar13 + 0x24) & 0xffdf;
          }
          iVar7 = piVar6[0x2e];
          (**(code **)(*DAT_803dd740 + 0x24))(iVar7,0);
          puVar9 = FUN_80037048(0x10,&local_58);
          dVar16 = (double)FLOAT_803e5218;
          for (iVar12 = 0; iVar12 < local_58; iVar12 = iVar12 + 1) {
            piVar11 = (int *)*puVar9;
            if (((piVar11 != piVar6) && (*(short *)((int)piVar11 + 0x46) == 0x519)) &&
               (dVar15 = (double)FUN_80021754((float *)(piVar6 + 6),(float *)(piVar11 + 6)),
               dVar15 < dVar16)) {
              (**(code **)(*DAT_803dd740 + 0x24))(iVar7,1);
              bVar3 = false;
              goto LAB_801a8b60;
            }
            puVar9 = puVar9 + 1;
          }
          bVar3 = true;
LAB_801a8b60:
          if (bVar3) {
            *(ushort *)(iVar13 + 0x24) = *(ushort *)(iVar13 + 0x24) | 1;
          }
          if ((*(ushort *)(iVar13 + 0x24) & 2) != 0) {
            FUN_801a8328(piVar6,0,0);
            *(ushort *)(iVar13 + 0x24) = *(ushort *)(iVar13 + 0x24) & 0xfffd;
          }
        }
        else {
          uVar2 = *(ushort *)(iVar13 + 0x24);
          if (((uVar2 & 0x400) == 0) && ((uVar2 & 1) != 0)) {
            if ((uVar2 & 0x20) == 0) {
              FUN_801a8328(piVar6,1,0);
            }
            else {
              FUN_801a8278((int)piVar6);
            }
            *(ushort *)(iVar13 + 0x24) = *(ushort *)(iVar13 + 0x24) & 0xfffe;
          }
          *(ushort *)(iVar13 + 0x24) = *(ushort *)(iVar13 + 0x24) | 2;
          if (*(char *)(iVar13 + 0x2e) != '\0') {
            if ((*(ushort *)(iVar13 + 0x24) & 0x400) == 0) {
              *(undefined *)(iVar13 + 0x2f) = 0;
            }
            else {
              uVar8 = FUN_80020078(0x894);
              *(char *)(iVar13 + 0x2f) = (char)uVar8;
            }
            FUN_8000bb38((uint)piVar6,0x108);
            FUN_8000b8a8((double)FLOAT_803e5220,(int)piVar6,0x40,
                         *(char *)(iVar13 + 0x2f) * ' ' + 0x20);
            fVar1 = (float)piVar6[10];
            local_50 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar13 + 0x2f));
            if (FLOAT_803e5224 *
                ((FLOAT_803e5200 * (float)(local_50 - DOUBLE_803e5240) + *(float *)(iVar13 + 0xc)) -
                (float)piVar6[4]) <= fVar1) {
              piVar6[10] = (int)(fVar1 - FLOAT_803e522c);
            }
            else {
              piVar6[10] = (int)(fVar1 + FLOAT_803e5228);
            }
            *(short *)(iVar13 + 0x26) = *(short *)(iVar13 + 0x26) + 0x1000;
            *(short *)(iVar13 + 0x28) = *(short *)(iVar13 + 0x28) + 0xdac;
            *(short *)(iVar13 + 0x2a) = *(short *)(iVar13 + 0x2a) + 0x800;
            FUN_8002ba34((double)FLOAT_803e51ec,(double)((float)piVar6[10] * FLOAT_803dc074),
                         (double)FLOAT_803e51ec,(int)piVar6);
            local_50 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar13 + 0x26));
            dVar16 = (double)FUN_802945e0();
            piVar6[4] = (int)(float)((double)(float)piVar6[4] + dVar16);
            if ((float)piVar6[4] < *(float *)(iVar13 + 0xc)) {
              piVar6[4] = (int)*(float *)(iVar13 + 0xc);
            }
            local_50 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar13 + 0x28));
            dVar16 = (double)FUN_802945e0();
            local_48 = (longlong)(int)((double)FLOAT_803e5238 * dVar16);
            *(short *)(piVar6 + 1) =
                 *(short *)(piVar6 + 1) + (short)(int)((double)FLOAT_803e5238 * dVar16);
            uStack_3c = (uint)*(ushort *)(iVar13 + 0x2a);
            local_40 = 0x43300000;
            dVar16 = (double)FUN_802945e0();
            local_38 = (longlong)(int)((double)FLOAT_803e5238 * dVar16);
            *(short *)((int)piVar6 + 2) =
                 *(short *)((int)piVar6 + 2) + (short)(int)((double)FLOAT_803e5238 * dVar16);
            DAT_803ad580 = FLOAT_803e5214;
            DAT_803ad584 = piVar6[3];
            DAT_803ad588 = *(float *)(iVar13 + 0xc);
            DAT_803ad58c = piVar6[5];
            local_54 = (int)((float)piVar6[4] - DAT_803ad588);
            local_30 = (longlong)local_54;
            (**(code **)(*DAT_803dd708 + 8))
                      (piVar6,0x723,&DAT_803ad578,0x200001,0xffffffff,&local_54);
          }
        }
      }
      else {
        uVar14 = FUN_801a80c4((int)piVar6);
        FUN_801a7f94(uVar14,dVar15,dVar16,in_f4,in_f5,in_f6,in_f7,in_f8,piVar6);
      }
    }
    else if (FLOAT_803e51ec < *(float *)(iVar13 + 0x14)) {
      *(float *)(iVar13 + 0x14) = *(float *)(iVar13 + 0x14) - FLOAT_803dc074;
      fVar5 = FLOAT_803e5214;
      fVar4 = FLOAT_803e51f0;
      if (fVar1 < *(float *)(iVar13 + 0x14)) {
        iVar7 = (int)(FLOAT_803e521c * (FLOAT_803e5214 - *(float *)(iVar13 + 0x14) / FLOAT_803e51f0)
                     );
        local_50 = (double)(longlong)iVar7;
        *(char *)((int)piVar6 + 0x36) = (char)iVar7;
        FUN_8009a010((double)FLOAT_803e5220,(double)(fVar5 - *(float *)(iVar13 + 0x14) / fVar4),
                     piVar6,2,(int *)0x0);
        FUN_8009a010((double)FLOAT_803e5220,
                     (double)(FLOAT_803e5214 - *(float *)(iVar13 + 0x14) / FLOAT_803e51f0),piVar6,2,
                     (int *)0x0);
      }
      else {
        *(undefined2 *)(iVar13 + 0x24) = 0;
        *(undefined *)((int)piVar6 + 0x36) = 0xff;
        FUN_80035ff8((int)piVar6);
        FUN_801a8328(piVar6,1,1);
      }
    }
  }
  FUN_8028688c();
  return;
}

