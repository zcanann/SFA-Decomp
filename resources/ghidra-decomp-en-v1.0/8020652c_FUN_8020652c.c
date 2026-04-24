// Function: FUN_8020652c
// Entry: 8020652c
// Size: 792 bytes

void FUN_8020652c(void)

{
  float fVar1;
  float fVar2;
  int iVar3;
  byte bVar5;
  char cVar6;
  int iVar4;
  int iVar7;
  ushort uVar8;
  int iVar9;
  int iVar10;
  int local_28;
  int local_24 [9];
  
  iVar3 = FUN_802860dc();
  iVar10 = *(int *)(iVar3 + 0x4c);
  iVar9 = *(int *)(iVar3 + 0xb8);
  uVar8 = 0xffff;
  bVar5 = (**(code **)(*DAT_803dcaac + 0x40))((int)*(char *)(iVar3 + 0xac));
  if (bVar5 == 2) {
    iVar4 = FUN_8001ffb4(0xe58);
    if (iVar4 != 0) {
      *(float *)(iVar3 + 0x10) = *(float *)(iVar10 + 0xc) - FLOAT_803e640c;
      goto LAB_8020682c;
    }
  }
  else if ((bVar5 < 2) && (bVar5 != 0)) {
    if (5 < *(byte *)(iVar9 + 5)) goto LAB_8020682c;
    iVar4 = FUN_8001ffb4(0xe57);
    if (iVar4 != 0) {
      *(float *)(iVar3 + 0x10) = *(float *)(iVar10 + 0xc) - FLOAT_803e640c;
      goto LAB_8020682c;
    }
  }
  cVar6 = FUN_8001ffb4(0x5e4);
  iVar4 = FUN_8001ffb4(0x5e5);
  if ((iVar4 != 0) || (cVar6 != *(char *)(iVar9 + 7))) {
    *(undefined *)(iVar9 + 4) = 0;
  }
  *(char *)(iVar9 + 7) = cVar6;
  if (*(int *)(iVar9 + 8) == 0) {
    iVar4 = FUN_8002e0fc(local_24,&local_28);
    for (; local_24[0] < local_28; local_24[0] = local_24[0] + 1) {
      iVar7 = *(int *)(iVar4 + local_24[0] * 4);
      if (*(short *)(iVar7 + 0x46) == 0x431) {
        *(int *)(iVar9 + 8) = iVar7;
        local_24[0] = local_28;
      }
    }
    if (*(int *)(iVar9 + 8) == 0) goto LAB_8020682c;
  }
  (**(code **)(**(int **)(*(int *)(iVar9 + 8) + 0x68) + 0x20))(*(int *)(iVar9 + 8),&DAT_80329a20);
  *(undefined *)(iVar9 + 6) = (&DAT_80329a20)[*(byte *)(iVar9 + 5)];
  if ((*(char *)(iVar9 + 4) == '\0') ||
     (*(float *)(iVar3 + 0x10) <= *(float *)(iVar10 + 0xc) - FLOAT_803e640c)) {
    if (*(char *)(iVar9 + 6) != '\0') {
      if (*(char *)(iVar9 + 4) == '\0') {
        *(undefined4 *)(iVar3 + 0x10) = *(undefined4 *)(iVar10 + 0xc);
      }
      if ((*(char *)(iVar9 + 4) == '\0') && (iVar10 = FUN_8002b9ec(), iVar10 != 0)) {
        fVar1 = *(float *)(iVar3 + 0x10) - *(float *)(iVar10 + 0x10);
        if (fVar1 < FLOAT_803e6418) {
          fVar1 = fVar1 * FLOAT_803e6414;
        }
        if (fVar1 < FLOAT_803e641c) {
          fVar1 = *(float *)(iVar10 + 0xc) - (*(float *)(iVar3 + 0xc) - FLOAT_803e641c);
          fVar2 = *(float *)(iVar3 + 0x14) - *(float *)(iVar10 + 0x14);
          if (fVar2 < FLOAT_803e6418) {
            fVar2 = fVar2 * FLOAT_803e6414;
          }
          if (fVar2 < FLOAT_803e6420) {
            if (fVar1 < FLOAT_803e6424) {
              if (fVar1 < FLOAT_803e641c) {
                if (fVar1 < FLOAT_803e6428) {
                  if (FLOAT_803e6418 <= fVar1) {
                    uVar8 = 1;
                  }
                }
                else {
                  uVar8 = 2;
                }
              }
              else {
                uVar8 = 3;
              }
            }
            else {
              uVar8 = 4;
            }
            if (uVar8 == *(byte *)(iVar9 + 6)) {
              *(undefined *)(iVar9 + 4) = 1;
            }
            else {
              FUN_800200e8(0x5e5,1);
            }
          }
        }
      }
    }
  }
  else {
    FUN_8000da58(iVar3,0x1c8);
    *(float *)(iVar3 + 0x10) = *(float *)(iVar3 + 0x10) - FLOAT_803db414 / FLOAT_803e6410;
    fVar1 = *(float *)(iVar10 + 0xc) - FLOAT_803e640c;
    if (*(float *)(iVar3 + 0x10) <= fVar1) {
      *(float *)(iVar3 + 0x10) = fVar1;
    }
  }
LAB_8020682c:
  FUN_80286128();
  return;
}

