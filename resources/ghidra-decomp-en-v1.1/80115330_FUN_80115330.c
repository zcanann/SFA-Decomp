// Function: FUN_80115330
// Entry: 80115330
// Size: 1468 bytes

/* WARNING: Removing unreachable block (ram,0x801158cc) */
/* WARNING: Removing unreachable block (ram,0x80115340) */

void FUN_80115330(void)

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
  local_48 = FLOAT_803e290c;
  sVar11 = 0;
  puVar6 = FUN_80039598();
  FUN_8002bac4();
  if (*(char *)(iVar10 + 0x601) == '\0') {
    if (((*(byte *)(iVar10 + 0x611) & 1) == 0) || (*(char *)(iVar10 + 0x600) == '\b')) {
      if (((*(byte *)(iVar10 + 0x611) & 1) == 0) &&
         ((*(char *)(iVar10 + 0x600) == '\b' &&
          (*(undefined *)(iVar10 + 0x600) = 0, (*(byte *)(iVar10 + 0x611) & 8) == 0)))) {
        FUN_8003adf4((int)puVar5,puVar6,(uint)*(byte *)(iVar10 + 0x610),iVar10 + 0x1c);
        *(undefined4 *)(iVar10 + 0x5f8) = 0x50;
      }
    }
    else {
      *(undefined *)(iVar10 + 0x600) = 8;
      if ((*(byte *)(iVar10 + 0x611) & 8) == 0) {
        FUN_8003adf4((int)puVar5,puVar6,(uint)*(byte *)(iVar10 + 0x610),iVar10 + 0x1c);
        *(undefined4 *)(iVar10 + 0x5f8) = 0x50;
        FUN_8003aab8(iVar10 + 0x1c,(uint)*(byte *)(iVar10 + 0x610),0,0);
      }
      else {
        puVar7 = FUN_80039598();
        FUN_8003ad0c((int)puVar5,puVar7,(uint)*(byte *)(iVar10 + 0x610));
      }
    }
    if (*(byte *)(iVar10 + 0x600) < 2) {
      iVar9 = *(int *)(iVar10 + 0x608);
      if (iVar9 == 0) {
        iVar9 = FUN_80036f50(8,puVar5,&local_48);
      }
      if (iVar9 != 0) {
        if ((*(byte *)(iVar10 + 0x611) & 0x20) != 0) {
          local_44 = *(float *)(iVar10 + 0x10) - *(float *)(iVar9 + 0xc);
          local_40 = *(float *)(iVar10 + 0x14) - *(float *)(iVar9 + 0x10);
          local_3c = *(float *)(iVar10 + 0x18) - *(float *)(iVar9 + 0x14);
          dVar12 = FUN_80293900((double)(local_44 * local_44 + local_3c * local_3c));
          if (dVar12 <= (double)FLOAT_803e2954) {
            fVar1 = (float)(dVar12 - (double)FLOAT_803e2958) / FLOAT_803e2950;
            fVar2 = FLOAT_803e2910;
            if ((FLOAT_803e2910 <= fVar1) && (fVar2 = fVar1, FLOAT_803e2924 < fVar1)) {
              fVar2 = FLOAT_803e2924;
            }
            fVar2 = FLOAT_803e2924 - fVar2;
            fVar1 = FLOAT_803e2924 - fVar2;
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
            FUN_8003adf4((int)puVar5,puVar6,(uint)*(byte *)(iVar10 + 0x610),iVar10 + 0x1c);
            *(undefined4 *)(iVar10 + 0x5f8) = 0x50;
            FUN_8003aab8(iVar10 + 0x1c,(uint)*(byte *)(iVar10 + 0x610),0,0);
            *(undefined *)(iVar10 + 0x600) = 0;
            goto LAB_801158cc;
          }
          if (*(int *)(iVar10 + 0x5f8) != 0) {
            uVar8 = FUN_8003a9ac(puVar5,puVar6,(uint)*(byte *)(iVar10 + 0x610),iVar10 + 0x1c);
            uVar3 = countLeadingZeros(uVar8);
            *(uint *)(iVar10 + 0x5f8) = uVar3 >> 5;
          }
          if (*(int *)(iVar10 + 0x620) < (int)-*(uint *)(iVar10 + 0x61c)) {
            uVar3 = FUN_80022264(*(uint *)(iVar10 + 0x61c),*(uint *)(iVar10 + 0x618));
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
          iVar4 = FUN_800386e0(puVar5,iVar9,(float *)0x0);
          sVar11 = (short)iVar4;
        }
        if ((*(byte *)(iVar10 + 0x611) & 0x10) != 0) {
          FUN_80039014('\0',1);
          sVar11 = sVar11 + -0x8000;
        }
        iVar4 = (int)sVar11;
        if (iVar4 < 0) {
          iVar4 = -iVar4;
        }
        if (((0x5555 < iVar4) || (iVar9 == 0)) ||
           (dVar12 = (double)FUN_800217c8((float *)(puVar5 + 0xc),(float *)(iVar9 + 0x18)),
           (double)*(float *)(iVar10 + 0x614) < dVar12)) {
          if ((*(char *)(iVar10 + 0x600) != '\0') ||
             ((iVar9 == 0 && (*(int *)(iVar10 + 0x604) != 0)))) {
            FUN_8003adf4((int)puVar5,puVar6,(uint)*(byte *)(iVar10 + 0x610),iVar10 + 0x1c);
            *(undefined4 *)(iVar10 + 0x5f8) = 10;
            FUN_8003aab8(iVar10 + 0x1c,(uint)*(byte *)(iVar10 + 0x610),0,0);
            *(undefined *)(iVar10 + 0x600) = 0;
          }
        }
        else {
          if ((iVar9 != *(int *)(iVar10 + 0x604)) || (*(char *)(iVar10 + 0x600) == '\0')) {
            FUN_8003adf4((int)puVar5,puVar6,(uint)*(byte *)(iVar10 + 0x610),iVar10 + 0x1c);
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
          FUN_8003a478(puVar5,iVar9,(float *)(iVar10 + 0x10),iVar4,(short *)(iVar10 + 0x5bc),8,
                       *(short *)(iVar10 + 0x60c));
          *(undefined *)(iVar10 + 0x600) = 1;
        }
        *(int *)(iVar10 + 0x604) = iVar9;
        if (*(int *)(iVar10 + 0x5f8) == 0) {
          *(undefined4 *)(iVar10 + 0x608) = 0;
        }
        if (((*(byte *)(iVar10 + 0x611) & 8) == 0) && (*(int *)(iVar10 + 0x5f8) != 0)) {
          uVar8 = FUN_8003a9ac(puVar5,puVar6,(uint)*(byte *)(iVar10 + 0x610),iVar10 + 0x1c);
          uVar3 = countLeadingZeros(uVar8);
          *(uint *)(iVar10 + 0x5f8) = uVar3 >> 5;
        }
      }
    }
    else if ((*(int *)(iVar10 + 0x5f8) == 0) || ((*(byte *)(iVar10 + 0x611) & 8) != 0)) {
      puVar6 = FUN_80039598();
      FUN_8003ad0c((int)puVar5,puVar6,(uint)*(byte *)(iVar10 + 0x610));
    }
    else {
      uVar8 = FUN_8003a9ac(puVar5,puVar6,(uint)*(byte *)(iVar10 + 0x610),iVar10 + 0x1c);
      uVar3 = countLeadingZeros(uVar8);
      *(uint *)(iVar10 + 0x5f8) = uVar3 >> 5;
    }
  }
LAB_801158cc:
  FUN_8028688c();
  return;
}

