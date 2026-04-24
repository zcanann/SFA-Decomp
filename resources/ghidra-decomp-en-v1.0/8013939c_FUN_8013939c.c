// Function: FUN_8013939c
// Entry: 8013939c
// Size: 1176 bytes

void FUN_8013939c(int param_1)

{
  bool bVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  double dVar5;
  float local_38;
  int local_34;
  float local_30;
  undefined auStack44 [12];
  undefined auStack32 [20];
  
  iVar4 = *(int *)(param_1 + 0xb8);
  bVar1 = false;
  local_38 = FLOAT_803e2424;
  iVar2 = FUN_8005b2fc((double)*(float *)(param_1 + 0x18),(double)*(float *)(param_1 + 0x1c),
                       (double)*(float *)(param_1 + 0x20));
  if ((iVar2 == -1) && ((*(uint *)(iVar4 + 0x54) & 0x80000) == 0)) {
    *(undefined *)(iVar4 + 0x353) = 0;
    *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(param_1 + 0x80);
    *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(param_1 + 0x84);
    *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(param_1 + 0x88);
  }
  *(uint *)(iVar4 + 0x54) = *(uint *)(iVar4 + 0x54) & 0xfff7ffff;
  if (*(char *)(iVar4 + 0x374) == '\0') {
    if ((*(uint *)(iVar4 + 0x54) & 0x2000) != 0) {
      bVar1 = true;
    }
  }
  else {
    *(char *)(iVar4 + 0x374) = *(char *)(iVar4 + 0x374) + -1;
    bVar1 = true;
  }
  if (bVar1) {
    FUN_800658a4((double)*(float *)(param_1 + 0x18),(double)*(float *)(param_1 + 0x1c),
                 (double)*(float *)(param_1 + 0x20),param_1,&local_30,0);
    *(float *)(param_1 + 0x10) = *(float *)(param_1 + 0x10) - local_30;
    *(undefined *)(iVar4 + 0x353) = 0;
  }
  if ((*(char *)(iVar4 + 0x353) == '\0') || ((*(byte *)(iVar4 + 0x58) >> 5 & 1) != 0)) {
    *(float *)(param_1 + 0x28) = FLOAT_803e23dc;
  }
  else {
    if (FLOAT_803e23dc == *(float *)(iVar4 + 0x2ac)) {
      bVar1 = false;
    }
    else if (FLOAT_803e2410 == *(float *)(iVar4 + 0x2b0)) {
      bVar1 = true;
    }
    else if (*(float *)(iVar4 + 0x2b4) - *(float *)(iVar4 + 0x2b0) <= FLOAT_803e2414) {
      bVar1 = false;
    }
    else {
      bVar1 = true;
    }
    if (bVar1) {
      *(float *)(param_1 + 0x28) = FLOAT_803e23dc;
      *(float *)(param_1 + 0x10) = *(float *)(iVar4 + 0x2b4) - FLOAT_803e23ec;
    }
    else {
      *(float *)(param_1 + 0x28) = FLOAT_803e2428 * FLOAT_803db414 + *(float *)(param_1 + 0x28);
      *(float *)(param_1 + 0x10) =
           *(float *)(param_1 + 0x28) * FLOAT_803db414 + *(float *)(param_1 + 0x10);
    }
  }
  local_34 = **(int **)(param_1 + 0x54);
  if (((*(ushort *)(*(int *)(param_1 + 0x54) + 0x60) & 8) == 0) ||
     (*(short *)(local_34 + 0x46) == 0x1f)) {
    local_34 = 0;
  }
  if ((*(uint *)(iVar4 + 0x54) & 8) == 0) {
    if ((*(int *)(iVar4 + 0x360) == 0) || (local_34 != *(int *)(iVar4 + 0x360))) {
      *(float *)(iVar4 + 0x364) = FLOAT_803e23dc;
    }
    else {
      *(float *)(iVar4 + 0x364) = *(float *)(iVar4 + 0x364) + FLOAT_803db414;
      if (FLOAT_803e23e0 <= *(float *)(iVar4 + 0x364)) {
        *(float *)(iVar4 + 0x364) = *(float *)(iVar4 + 0x364) - FLOAT_803e23e0;
        *(uint *)(iVar4 + 0x54) = *(uint *)(iVar4 + 0x54) | 8;
        *(undefined *)(*(int *)(param_1 + 0x50) + 0x71) = 0x7e;
      }
    }
  }
  else {
    *(float *)(iVar4 + 0x364) = *(float *)(iVar4 + 0x364) + FLOAT_803db414;
    if (FLOAT_803e242c <= *(float *)(iVar4 + 0x364)) {
      iVar2 = FUN_8002b9ec();
      dVar5 = (double)FUN_800216d0(param_1 + 0x18,iVar2 + 0x18);
      if ((double)FLOAT_803e2430 < dVar5) {
        *(float *)(iVar4 + 0x364) = *(float *)(iVar4 + 0x364) - FLOAT_803e242c;
        *(undefined *)(*(int *)(param_1 + 0x50) + 0x71) = 0x7f;
        *(uint *)(iVar4 + 0x54) = *(uint *)(iVar4 + 0x54) & 0xfffffff7;
      }
    }
  }
  *(int *)(iVar4 + 0x360) = local_34;
  uVar3 = FUN_80037a68(param_1,iVar4 + 0x370,&local_34,auStack32);
  *(undefined4 *)(iVar4 + 0x368) = uVar3;
  switch(*(undefined4 *)(iVar4 + 0x368)) {
  case 1:
  case 2:
  case 4:
  case 5:
  case 0xe:
  case 0xf:
  case 0x11:
  case 0x13:
    FUN_8009a1dc((double)FLOAT_803e2434,param_1,auStack44,1,0);
    break;
  case 7:
  case 8:
  case 9:
  case 10:
  case 0xb:
  case 0xc:
    FUN_80096f9c(auStack32,8,0xff,0x20,0x20);
    FUN_8009a1dc((double)FLOAT_803e2434,param_1,auStack44,4,0);
    if (*(short *)(local_34 + 0x46) == 0x69) {
      FUN_8000bb18(param_1,0x23f);
    }
    break;
  case 0x1f:
    *(float *)(iVar4 + 0x838) = FLOAT_803e2438;
  }
  if (*(char *)(iVar4 + 0x353) == '\0') {
    (**(code **)(*DAT_803dcaa8 + 0x20))(param_1,iVar4 + 0xf8);
  }
  iVar2 = FUN_8005afac((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x14));
  if ((iVar2 == 0xe) || (iVar2 = FUN_80036e58(5,param_1,&local_38), iVar2 != 0)) {
    *(uint *)(iVar4 + 0xf8) = *(uint *)(iVar4 + 0xf8) & 0xfffffffb;
  }
  else {
    *(uint *)(iVar4 + 0xf8) = *(uint *)(iVar4 + 0xf8) | 4;
  }
  (**(code **)(*DAT_803dcaa8 + 0x10))((double)FLOAT_803db414,param_1,iVar4 + 0xf8);
  (**(code **)(*DAT_803dcaa8 + 0x14))(param_1,iVar4 + 0xf8);
  (**(code **)(*DAT_803dcaa8 + 0x18))((double)FLOAT_803db414,param_1,iVar4 + 0xf8);
  *(undefined2 *)(param_1 + 2) = *(undefined2 *)(iVar4 + 0x290);
  *(undefined2 *)(param_1 + 4) = *(undefined2 *)(iVar4 + 0x292);
  return;
}

