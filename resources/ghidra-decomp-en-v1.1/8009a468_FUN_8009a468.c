// Function: FUN_8009a468
// Entry: 8009a468
// Size: 1772 bytes

void FUN_8009a468(undefined4 param_1,undefined4 param_2,uint param_3,int *param_4)

{
  undefined4 uVar1;
  char cVar2;
  int iVar3;
  undefined8 uVar4;
  undefined local_28 [40];
  
  uVar4 = FUN_8028683c();
  uVar1 = (undefined4)((ulonglong)uVar4 >> 0x20);
  iVar3 = (int)uVar4;
  switch(param_3 & 0xff) {
  case 1:
    local_28[0] = 1;
    for (cVar2 = '\n'; cVar2 != '\0'; cVar2 = cVar2 + -1) {
      (**(code **)(*DAT_803dd708 + 8))(uVar1,0x325,iVar3,0x200001,0xffffffff,local_28);
      (**(code **)(*DAT_803dd708 + 8))(uVar1,0x323,iVar3,0x200001,0xffffffff,local_28);
    }
    for (cVar2 = '\x04'; cVar2 != '\0'; cVar2 = cVar2 + -1) {
      (**(code **)(*DAT_803dd708 + 8))(uVar1,0x326,iVar3,0x200001,0xffffffff,local_28);
    }
    break;
  case 2:
    local_28[0] = 2;
    for (cVar2 = '\r'; cVar2 != '\0'; cVar2 = cVar2 + -1) {
      (**(code **)(*DAT_803dd708 + 8))(uVar1,0x325,iVar3,0x200001,0xffffffff,local_28);
      (**(code **)(*DAT_803dd708 + 8))(uVar1,0x323,iVar3,0x200001,0xffffffff,local_28);
    }
    for (cVar2 = '\x06'; cVar2 != '\0'; cVar2 = cVar2 + -1) {
      (**(code **)(*DAT_803dd708 + 8))(uVar1,0x326,iVar3,0x200001,0xffffffff,local_28);
    }
    break;
  case 3:
    local_28[0] = 3;
    for (cVar2 = '\x1e'; cVar2 != '\0'; cVar2 = cVar2 + -1) {
      (**(code **)(*DAT_803dd708 + 8))(uVar1,0x325,iVar3,0x200001,0xffffffff,local_28);
      (**(code **)(*DAT_803dd708 + 8))(uVar1,0x323,iVar3,0x200001,0xffffffff,local_28);
    }
    for (cVar2 = '\b'; cVar2 != '\0'; cVar2 = cVar2 + -1) {
      (**(code **)(*DAT_803dd708 + 8))(uVar1,0x326,iVar3,0x200001,0xffffffff,local_28);
    }
    break;
  case 4:
    for (cVar2 = '\a'; cVar2 != '\0'; cVar2 = cVar2 + -1) {
      (**(code **)(*DAT_803dd708 + 8))(uVar1,0x328,iVar3,0x200001,0xffffffff,0);
    }
    break;
  case 5:
    local_28[0] = 4;
    for (cVar2 = '\n'; cVar2 != '\0'; cVar2 = cVar2 + -1) {
      (**(code **)(*DAT_803dd708 + 8))(uVar1,0x323,iVar3,0x200001,0xffffffff,local_28);
    }
    for (cVar2 = '\x04'; cVar2 != '\0'; cVar2 = cVar2 + -1) {
      (**(code **)(*DAT_803dd708 + 8))(uVar1,0x326,iVar3,0x200001,0xffffffff,local_28);
    }
    break;
  case 6:
    local_28[0] = 5;
    for (cVar2 = '\n'; cVar2 != '\0'; cVar2 = cVar2 + -1) {
      (**(code **)(*DAT_803dd708 + 8))(uVar1,0x323,iVar3,0x200001,0xffffffff,local_28);
    }
    for (cVar2 = '\x04'; cVar2 != '\0'; cVar2 = cVar2 + -1) {
      (**(code **)(*DAT_803dd708 + 8))(uVar1,0x326,iVar3,0x200001,0xffffffff,local_28);
    }
    break;
  case 7:
    local_28[0] = 6;
    for (cVar2 = '\n'; cVar2 != '\0'; cVar2 = cVar2 + -1) {
      (**(code **)(*DAT_803dd708 + 8))(uVar1,0x323,iVar3,0x200001,0xffffffff,local_28);
    }
    for (cVar2 = '\x04'; cVar2 != '\0'; cVar2 = cVar2 + -1) {
      (**(code **)(*DAT_803dd708 + 8))(uVar1,0x326,iVar3,0x200001,0xffffffff,local_28);
    }
    break;
  case 8:
    local_28[0] = 7;
    for (cVar2 = '\n'; cVar2 != '\0'; cVar2 = cVar2 + -1) {
      (**(code **)(*DAT_803dd708 + 8))(uVar1,0x323,iVar3,0x200001,0xffffffff,local_28);
    }
    for (cVar2 = '\x04'; cVar2 != '\0'; cVar2 = cVar2 + -1) {
      (**(code **)(*DAT_803dd708 + 8))(uVar1,0x326,iVar3,0x200001,0xffffffff,local_28);
    }
    break;
  case 9:
    local_28[0] = 8;
    for (cVar2 = '\n'; cVar2 != '\0'; cVar2 = cVar2 + -1) {
      (**(code **)(*DAT_803dd708 + 8))(uVar1,0x323,iVar3,0x200001,0xffffffff,local_28);
    }
    for (cVar2 = '\x04'; cVar2 != '\0'; cVar2 = cVar2 + -1) {
      (**(code **)(*DAT_803dd708 + 8))(uVar1,0x326,iVar3,0x200001,0xffffffff,local_28);
    }
  }
  if (param_4 != (int *)0x0) {
    FUN_8001dbf0((int)param_4,2);
    FUN_8001de4c((double)*(float *)(iVar3 + 0xc),(double)(FLOAT_803e0004 + *(float *)(iVar3 + 0x10))
                 ,(double)*(float *)(iVar3 + 0x14),param_4);
    iVar3 = (param_3 & 0xff) * 3;
    FUN_8001dbb4((int)param_4,(&DAT_803105f0)[iVar3],(&DAT_803105f1)[iVar3],(&DAT_803105f2)[iVar3],
                 0xff);
    FUN_8001dadc((int)param_4,(&DAT_803105f0)[iVar3],(&DAT_803105f1)[iVar3],(&DAT_803105f2)[iVar3],
                 0xff);
    FUN_8001dcfc((double)FLOAT_803e0014,(double)FLOAT_803e001c,(int)param_4);
    FUN_8001dc18((int)param_4,0);
    FUN_8001dc30((double)FLOAT_803dffdc,(int)param_4,'\x01');
    FUN_8001dc30((double)FLOAT_803dffd8,(int)param_4,'\0');
    FUN_8001d6e4((int)param_4,0,0);
    FUN_8001de04((int)param_4,1);
  }
  FUN_80286888();
  return;
}

