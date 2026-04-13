// Function: FUN_80139724
// Entry: 80139724
// Size: 1176 bytes

void FUN_80139724(uint param_1)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  double dVar4;
  float local_38;
  int local_34;
  float local_30;
  undefined auStack_2c [12];
  float afStack_20 [5];
  
  iVar3 = *(int *)(param_1 + 0xb8);
  bVar1 = false;
  local_38 = FLOAT_803e30b4;
  iVar2 = FUN_8005b478((double)*(float *)(param_1 + 0x18),(double)*(float *)(param_1 + 0x1c));
  if ((iVar2 == -1) && ((*(uint *)(iVar3 + 0x54) & 0x80000) == 0)) {
    *(undefined *)(iVar3 + 0x353) = 0;
    *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(param_1 + 0x80);
    *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(param_1 + 0x84);
    *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(param_1 + 0x88);
  }
  *(uint *)(iVar3 + 0x54) = *(uint *)(iVar3 + 0x54) & 0xfff7ffff;
  if (*(char *)(iVar3 + 0x374) == '\0') {
    if ((*(uint *)(iVar3 + 0x54) & 0x2000) != 0) {
      bVar1 = true;
    }
  }
  else {
    *(char *)(iVar3 + 0x374) = *(char *)(iVar3 + 0x374) + -1;
    bVar1 = true;
  }
  if (bVar1) {
    FUN_80065a20((double)*(float *)(param_1 + 0x18),(double)*(float *)(param_1 + 0x1c),
                 (double)*(float *)(param_1 + 0x20),param_1,&local_30,0);
    *(float *)(param_1 + 0x10) = *(float *)(param_1 + 0x10) - local_30;
    *(undefined *)(iVar3 + 0x353) = 0;
  }
  if ((*(char *)(iVar3 + 0x353) == '\0') || ((*(byte *)(iVar3 + 0x58) >> 5 & 1) != 0)) {
    *(float *)(param_1 + 0x28) = FLOAT_803e306c;
  }
  else {
    if (FLOAT_803e306c == *(float *)(iVar3 + 0x2ac)) {
      bVar1 = false;
    }
    else if (FLOAT_803e30a0 == *(float *)(iVar3 + 0x2b0)) {
      bVar1 = true;
    }
    else if (*(float *)(iVar3 + 0x2b4) - *(float *)(iVar3 + 0x2b0) <= FLOAT_803e30a4) {
      bVar1 = false;
    }
    else {
      bVar1 = true;
    }
    if (bVar1) {
      *(float *)(param_1 + 0x28) = FLOAT_803e306c;
      *(float *)(param_1 + 0x10) = *(float *)(iVar3 + 0x2b4) - FLOAT_803e307c;
    }
    else {
      *(float *)(param_1 + 0x28) = FLOAT_803e30b8 * FLOAT_803dc074 + *(float *)(param_1 + 0x28);
      *(float *)(param_1 + 0x10) =
           *(float *)(param_1 + 0x28) * FLOAT_803dc074 + *(float *)(param_1 + 0x10);
    }
  }
  local_34 = **(int **)(param_1 + 0x54);
  if (((*(ushort *)(*(int *)(param_1 + 0x54) + 0x60) & 8) == 0) ||
     (*(short *)(local_34 + 0x46) == 0x1f)) {
    local_34 = 0;
  }
  if ((*(uint *)(iVar3 + 0x54) & 8) == 0) {
    if ((*(int *)(iVar3 + 0x360) == 0) || (local_34 != *(int *)(iVar3 + 0x360))) {
      *(float *)(iVar3 + 0x364) = FLOAT_803e306c;
    }
    else {
      *(float *)(iVar3 + 0x364) = *(float *)(iVar3 + 0x364) + FLOAT_803dc074;
      if (FLOAT_803e3070 <= *(float *)(iVar3 + 0x364)) {
        *(float *)(iVar3 + 0x364) = *(float *)(iVar3 + 0x364) - FLOAT_803e3070;
        *(uint *)(iVar3 + 0x54) = *(uint *)(iVar3 + 0x54) | 8;
        *(undefined *)(*(int *)(param_1 + 0x50) + 0x71) = 0x7e;
      }
    }
  }
  else {
    *(float *)(iVar3 + 0x364) = *(float *)(iVar3 + 0x364) + FLOAT_803dc074;
    if (FLOAT_803e30bc <= *(float *)(iVar3 + 0x364)) {
      iVar2 = FUN_8002bac4();
      dVar4 = FUN_80021794((float *)(param_1 + 0x18),(float *)(iVar2 + 0x18));
      if ((double)FLOAT_803e30c0 < dVar4) {
        *(float *)(iVar3 + 0x364) = *(float *)(iVar3 + 0x364) - FLOAT_803e30bc;
        *(undefined *)(*(int *)(param_1 + 0x50) + 0x71) = 0x7f;
        *(uint *)(iVar3 + 0x54) = *(uint *)(iVar3 + 0x54) & 0xfffffff7;
      }
    }
  }
  *(int *)(iVar3 + 0x360) = local_34;
  iVar2 = FUN_80037b60(param_1,(float *)(iVar3 + 0x370),&local_34,afStack_20);
  *(int *)(iVar3 + 0x368) = iVar2;
  switch(*(undefined4 *)(iVar3 + 0x368)) {
  case 1:
  case 2:
  case 4:
  case 5:
  case 0xe:
  case 0xf:
  case 0x11:
  case 0x13:
    FUN_8009a468(param_1,auStack_2c,1,(int *)0x0);
    break;
  case 7:
  case 8:
  case 9:
  case 10:
  case 0xb:
  case 0xc:
    FUN_80097228(afStack_20,8,0xff,0x20,0x20);
    FUN_8009a468(param_1,auStack_2c,4,(int *)0x0);
    if (*(short *)(local_34 + 0x46) == 0x69) {
      FUN_8000bb38(param_1,0x23f);
    }
    break;
  case 0x1f:
    *(float *)(iVar3 + 0x838) = FLOAT_803e30c8;
  }
  if (*(char *)(iVar3 + 0x353) == '\0') {
    (**(code **)(*DAT_803dd728 + 0x20))(param_1,iVar3 + 0xf8);
  }
  iVar2 = FUN_8005b128();
  if ((iVar2 == 0xe) || (iVar2 = FUN_80036f50(5,param_1,&local_38), iVar2 != 0)) {
    *(uint *)(iVar3 + 0xf8) = *(uint *)(iVar3 + 0xf8) & 0xfffffffb;
  }
  else {
    *(uint *)(iVar3 + 0xf8) = *(uint *)(iVar3 + 0xf8) | 4;
  }
  (**(code **)(*DAT_803dd728 + 0x10))((double)FLOAT_803dc074,param_1,iVar3 + 0xf8);
  (**(code **)(*DAT_803dd728 + 0x14))(param_1,iVar3 + 0xf8);
  (**(code **)(*DAT_803dd728 + 0x18))((double)FLOAT_803dc074,param_1,iVar3 + 0xf8);
  *(undefined2 *)(param_1 + 2) = *(undefined2 *)(iVar3 + 0x290);
  *(undefined2 *)(param_1 + 4) = *(undefined2 *)(iVar3 + 0x292);
  return;
}

