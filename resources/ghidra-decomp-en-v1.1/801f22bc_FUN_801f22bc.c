// Function: FUN_801f22bc
// Entry: 801f22bc
// Size: 624 bytes

void FUN_801f22bc(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)

{
  char cVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  int iVar5;
  undefined uVar8;
  float *pfVar6;
  uint uVar7;
  int iVar9;
  float fVar10;
  int iVar11;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined2 *puVar12;
  undefined8 uVar13;
  int local_18 [3];
  
  puVar12 = *(undefined2 **)(param_9 + 0xb8);
  iVar5 = FUN_8002bac4();
  if (*(char *)((int)puVar12 + 5) == '\0') {
    uVar8 = 0;
    if (((*(byte *)(param_9 + 0xaf) & 1) != 0) && (*(int *)(param_9 + 0xf8) == 0)) {
      *puVar12 = 0;
      puVar12[1] = 0x28;
      FUN_80014b68(0,0x100);
      uVar8 = 1;
    }
    *(undefined *)((int)puVar12 + 5) = uVar8;
    if (*(char *)((int)puVar12 + 5) != '\0') {
      *(undefined *)(puVar12 + 3) = 1;
    }
    if (*(int *)(param_9 + 0xf8) == 0) {
      FUN_80036018(param_9);
      *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) & 0xf7;
      *(float *)(param_9 + 0x28) = -(FLOAT_803e6a1c * FLOAT_803dc074 - *(float *)(param_9 + 0x28));
      *(float *)(param_9 + 0x10) =
           *(float *)(param_9 + 0x28) * FLOAT_803dc074 + *(float *)(param_9 + 0x10);
      iVar5 = FUN_80065fcc((double)*(float *)(param_9 + 0xc),(double)*(float *)(param_9 + 0x10),
                           (double)*(float *)(param_9 + 0x14),param_9,local_18,0,1);
      fVar4 = FLOAT_803e6a24;
      fVar3 = FLOAT_803e6a20;
      fVar10 = 0.0;
      iVar11 = 0;
      iVar9 = 0;
      if (0 < iVar5) {
        do {
          pfVar6 = *(float **)(local_18[0] + iVar9);
          if (*(char *)(pfVar6 + 5) != '\x0e') {
            fVar2 = *pfVar6;
            if ((*(float *)(param_9 + 0x10) < fVar2) &&
               ((fVar2 - fVar3 < *(float *)(param_9 + 0x10) || (iVar11 == 0)))) {
              fVar10 = pfVar6[4];
              *(float *)(param_9 + 0x10) = fVar2;
              *(float *)(param_9 + 0x28) = fVar4;
            }
          }
          iVar9 = iVar9 + 4;
          iVar11 = iVar11 + 1;
          iVar5 = iVar5 + -1;
        } while (iVar5 != 0);
      }
      if (fVar10 != 0.0) {
        iVar5 = *(int *)((int)fVar10 + 0x58);
        cVar1 = *(char *)(iVar5 + 0x10f);
        *(char *)(iVar5 + 0x10f) = cVar1 + '\x01';
        *(uint *)(iVar5 + cVar1 * 4 + 0x100) = param_9;
      }
    }
  }
  else {
    uVar13 = FUN_80035ff8(param_9);
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
    uVar7 = FUN_80014e9c(0);
    if ((uVar7 & 0x100) != 0) {
      *(undefined *)(puVar12 + 3) = 0;
      uVar13 = FUN_80014b68(0,0x100);
    }
    if (*(int *)(param_9 + 0xf8) == 1) {
      *(undefined *)((int)puVar12 + 5) = 2;
    }
    if ((*(char *)((int)puVar12 + 5) == '\x02') && (*(int *)(param_9 + 0xf8) == 0)) {
      *(undefined *)((int)puVar12 + 5) = 0;
      *(undefined *)(puVar12 + 3) = 0;
    }
    if (*(char *)(puVar12 + 3) != '\0') {
      FUN_800379bc(uVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar5,0x100008,
                   param_9,CONCAT22(puVar12[1],*puVar12),in_r7,in_r8,in_r9,in_r10);
    }
  }
  return;
}

