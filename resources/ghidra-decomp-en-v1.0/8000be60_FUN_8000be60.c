// Function: FUN_8000be60
// Entry: 8000be60
// Size: 604 bytes

/* WARNING: Removing unreachable block (ram,0x8000c098) */

void FUN_8000be60(int param_1,undefined4 *param_2,uint param_3,short param_4)

{
  bool bVar1;
  int iVar2;
  undefined4 uVar3;
  undefined uVar4;
  undefined4 *puVar5;
  undefined4 uVar6;
  double dVar7;
  undefined8 in_f31;
  double dVar8;
  int local_50;
  short local_4c;
  undefined local_4a [2];
  undefined2 local_48 [2];
  undefined4 local_44;
  int local_40;
  uint local_3c;
  float local_38;
  undefined4 local_34;
  float local_30;
  undefined auStack44 [16];
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  bVar1 = false;
  local_50 = param_1;
  local_4c = param_4;
  iVar2 = FUN_8000c0bc(&local_50,&local_4c);
  if (iVar2 != 0) {
    uVar3 = FUN_8000c400(local_4c);
    iVar2 = FUN_8000c1a8(uVar3,local_48,local_4a,&local_30,&local_34,&local_38,&local_3c,&local_40,
                         &local_44);
    if (iVar2 != 0) {
      if ((local_50 != 0) && (param_2 == (undefined4 *)0x0)) {
        param_2 = (undefined4 *)(local_50 + 0x18);
        bVar1 = true;
      }
      if (param_2 != (undefined4 *)0x0) {
        dVar8 = (double)local_38;
        dVar7 = (double)FUN_8000cbc0(param_2,auStack44);
        if (dVar8 < dVar7) goto LAB_8000c098;
      }
      if ((param_3 & 0xff) != 0) {
        local_3c = param_3 & 0xff;
      }
      if ((local_50 == 0) || (local_3c == 0)) {
        if (local_4c == 0) {
          puVar5 = (undefined4 *)0x0;
        }
        else {
          puVar5 = (undefined4 *)FUN_8000ccec(local_50,0,local_4c,1);
        }
        if ((puVar5 != (undefined4 *)0x0) && ((local_40 != 0 || (DAT_803dc83c == 3)))) {
          FUN_80272868(*puVar5);
          *puVar5 = 0xffffffff;
        }
      }
      else {
        if (((local_3c & 0xff) == 0) || (local_50 == 0)) {
          puVar5 = (undefined4 *)0x0;
        }
        else {
          puVar5 = (undefined4 *)FUN_8000ccec(local_50,local_3c & 0xff,0,0);
        }
        if (puVar5 != (undefined4 *)0x0) {
          if (local_40 == 0) goto LAB_8000c098;
          FUN_80272868(*puVar5);
          *puVar5 = 0xffffffff;
        }
      }
      iVar2 = FUN_8000c4b8((double)local_30,local_48[0],local_4a[0],0x40,local_44);
      if (iVar2 != 0) {
        *(short *)(iVar2 + 0x1e) = local_4c;
        *(short *)(iVar2 + 0x1c) = (short)local_3c;
        *(int *)(iVar2 + 0x18) = local_50;
        if (param_2 == (undefined4 *)0x0) {
          *(undefined *)(iVar2 + 7) = 0x7f;
        }
        else {
          *(undefined4 *)(iVar2 + 0x20) = local_34;
          *(float *)(iVar2 + 0x24) = local_38;
          *(undefined *)(iVar2 + 4) = 1;
          uVar4 = 0;
          if ((bVar1) && (local_3c != 0)) {
            uVar4 = 1;
          }
          *(undefined *)(iVar2 + 5) = uVar4;
          *(undefined4 *)(iVar2 + 0xc) = *param_2;
          *(undefined4 *)(iVar2 + 0x10) = param_2[1];
          *(undefined4 *)(iVar2 + 0x14) = param_2[2];
          FUN_8000c6c0();
        }
      }
    }
  }
LAB_8000c098:
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  return;
}

