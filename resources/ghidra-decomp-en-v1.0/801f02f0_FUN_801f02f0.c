// Function: FUN_801f02f0
// Entry: 801f02f0
// Size: 740 bytes

void FUN_801f02f0(undefined2 *param_1)

{
  int iVar1;
  int iVar2;
  char cVar3;
  undefined4 *puVar4;
  
  iVar1 = FUN_8001ffb4(0x78);
  if (iVar1 == 0) {
    if (param_1[0x23] == 0x188) {
      *(undefined *)(param_1 + 0x1b) = 0x80;
    }
    else {
      iVar1 = FUN_8002b9ec();
      puVar4 = *(undefined4 **)(param_1 + 0x5c);
      iVar2 = FUN_8001ffb4(0x429);
      if (iVar2 == 0) {
        iVar2 = FUN_8001ffb4(0xd0);
        if ((iVar2 == 0) &&
           (cVar3 = (**(code **)(*DAT_803dcaac + 0x4c))(*(undefined *)(param_1 + 0x1a),2),
           cVar3 == '\0')) {
          (**(code **)(*DAT_803dcaac + 0x50))(*(undefined *)(param_1 + 0x1a),1,1);
          (**(code **)(*DAT_803dcaac + 0x50))(*(undefined *)(param_1 + 0x1a),2,1);
        }
      }
      else {
        cVar3 = (**(code **)(*DAT_803dcaac + 0x4c))(*(undefined *)(param_1 + 0x1a),2);
        if (cVar3 != '\0') {
          (**(code **)(*DAT_803dcaac + 0x50))(*(undefined *)(param_1 + 0x1a),1,0);
          (**(code **)(*DAT_803dcaac + 0x50))(*(undefined *)(param_1 + 0x1a),2,0);
        }
      }
      iVar2 = FUN_8001ffb4(0xd0);
      if (iVar2 == 0) {
        if ((*(char *)(puVar4 + 3) == '\0') && (iVar2 = FUN_8001ffb4(0x429), iVar2 == 0)) {
          (**(code **)(*DAT_803dcaac + 0x50))(*(undefined *)(param_1 + 0x1a),1,1);
          (**(code **)(*DAT_803dcaac + 0x50))(*(undefined *)(param_1 + 0x1a),2,1);
          *(undefined *)(puVar4 + 3) = 1;
        }
      }
      else {
        cVar3 = (**(code **)(*DAT_803dcaac + 0x4c))(*(undefined *)(param_1 + 0x1a),4);
        if (cVar3 == '\0') {
          (**(code **)(*DAT_803dcaac + 0x50))(*(undefined *)(param_1 + 0x1a),4,1);
        }
        if (*(char *)(puVar4 + 3) != '\0') {
          *(undefined *)(puVar4 + 3) = 0;
        }
      }
      iVar2 = FUN_8001ffb4(0xa4);
      if (iVar2 == 0) {
        *(float *)(iVar1 + 0xc) = FLOAT_803e5cec;
        *(float *)(iVar1 + 0x10) = FLOAT_803e5cf0;
        *(float *)(iVar1 + 0x14) = FLOAT_803e5cf4;
        FUN_80062e84(iVar1,param_1,0);
        FUN_80296bbc(iVar1);
        *(undefined4 *)(param_1 + 0x7c) = 1;
      }
      else {
        *(undefined4 *)(param_1 + 0x7a) = 10;
        if (*(int *)(param_1 + 0x7c) == 1) {
          *(undefined4 *)(param_1 + 6) = *puVar4;
          *(undefined4 *)(param_1 + 8) = puVar4[1];
          *(undefined4 *)(param_1 + 10) = puVar4[2];
          *param_1 = *(undefined2 *)((int)puVar4 + 0xe);
          (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,0xffffffff);
          *(undefined4 *)(param_1 + 0x7c) = 2;
        }
      }
    }
  }
  return;
}

