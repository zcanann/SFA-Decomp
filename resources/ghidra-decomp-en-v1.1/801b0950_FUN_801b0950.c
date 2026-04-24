// Function: FUN_801b0950
// Entry: 801b0950
// Size: 520 bytes

void FUN_801b0950(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  undefined uVar1;
  float fVar2;
  uint uVar3;
  undefined2 *puVar4;
  undefined4 uVar5;
  int iVar6;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar7;
  int iVar8;
  int iVar9;
  
  iVar8 = *(int *)(param_9 + 0xb8);
  iVar9 = *(int *)(param_9 + 0x4c);
  uVar3 = FUN_80020078((int)*(short *)(iVar9 + 0x24));
  *(char *)(iVar8 + 0x1a) = (char)uVar3;
  if (*(char *)(iVar8 + 0x1b) != '\0') {
    uVar3 = FUN_80020078((int)*(short *)(iVar9 + 0x1e));
    if (uVar3 == 0) {
      *(undefined *)(iVar8 + 0x1a) = 0;
    }
    else {
      *(undefined *)(iVar8 + 0x1a) = 1;
      *(undefined *)(iVar8 + 0x1b) = 0;
      *(float *)(iVar8 + 0xc) = FLOAT_803e54ac;
    }
  }
  if ((*(int *)(iVar8 + 8) == 0) && (uVar3 = FUN_8002e144(), (uVar3 & 0xff) != 0)) {
    puVar4 = FUN_8002becc(0x24,0x18d);
    *(undefined *)(puVar4 + 1) = 9;
    *(undefined *)(puVar4 + 2) = 2;
    *(undefined *)(puVar4 + 3) = 0xff;
    *(undefined *)((int)puVar4 + 5) = 4;
    *(undefined *)((int)puVar4 + 7) = 0x50;
    *(undefined4 *)(puVar4 + 4) = *(undefined4 *)(param_9 + 0xc);
    *(undefined4 *)(puVar4 + 6) = *(undefined4 *)(param_9 + 0x10);
    *(undefined4 *)(puVar4 + 8) = *(undefined4 *)(param_9 + 0x14);
    *(undefined *)(puVar4 + 0xc) = *(undefined *)(iVar9 + 0x1c);
    puVar4[0xd] = (ushort)*(byte *)(iVar9 + 0x1a);
    puVar4[0xe] = (ushort)*(byte *)(iVar9 + 0x1b);
    *(undefined4 *)(puVar4 + 10) = *(undefined4 *)(iVar9 + 0x14);
    uVar5 = FUN_8002e088(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar4,5,
                         *(undefined *)(param_9 + 0xac),0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
    *(undefined4 *)(iVar8 + 8) = uVar5;
  }
  iVar7 = *(int *)(iVar8 + 8);
  fVar2 = *(float *)(iVar8 + 0xc) - FLOAT_803dc074;
  *(float *)(iVar8 + 0xc) = fVar2;
  if ((fVar2 <= FLOAT_803e54ac) &&
     (iVar6 = (**(code **)(**(int **)(iVar7 + 0x68) + 0x24))(iVar7), iVar6 != 0)) {
    if (*(char *)(iVar8 + 0x1a) != '\0') {
      uVar3 = FUN_80020078((int)*(short *)(iVar9 + 0x1e));
      if ((uVar3 == 0) || (*(char *)(iVar8 + 0x18) != '\0')) {
        uVar1 = *(undefined *)(iVar9 + 0x1a);
      }
      else {
        uVar1 = *(undefined *)(iVar9 + 0x20);
        *(undefined *)(iVar8 + 0x18) = 1;
      }
      (**(code **)(**(int **)(iVar7 + 0x68) + 0x20))(iVar7,uVar1,*(undefined *)(iVar9 + 0x1b));
    }
    uVar3 = FUN_80022264(0,0x3c);
    *(float *)(iVar8 + 0xc) =
         *(float *)(iVar8 + 0x10) +
         (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e54b0);
  }
  return;
}

