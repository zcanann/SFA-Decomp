// Function: FUN_80252f44
// Entry: 80252f44
// Size: 312 bytes

undefined4 FUN_80252f44(int param_1,code *param_2)

{
  code *pcVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  
  uVar2 = FUN_8024377c();
  uVar3 = FUN_80252d80(param_1);
  if ((*(uint *)(&DAT_8032e254 + param_1 * 4) & 0x80) == 0) {
    (*param_2)(param_1,uVar3);
  }
  else {
    param_1 = param_1 * 0x10;
    pcVar1 = *(code **)(&DAT_803ae360 + param_1);
    if (pcVar1 != param_2) {
      if (pcVar1 == (code *)0x0) {
        *(code **)(&DAT_803ae360 + param_1) = param_2;
      }
      else if (*(code **)(&DAT_803ae364 + param_1) != param_2) {
        if (*(code **)(&DAT_803ae364 + param_1) == (code *)0x0) {
          *(code **)(&DAT_803ae364 + param_1) = param_2;
        }
        else if (*(code **)(&DAT_803ae368 + param_1) != param_2) {
          if (*(code **)(&DAT_803ae368 + param_1) == (code *)0x0) {
            *(code **)(&DAT_803ae368 + param_1) = param_2;
          }
          else if ((*(code **)(&DAT_803ae36c + param_1) != param_2) &&
                  (*(code **)(&DAT_803ae36c + param_1) == (code *)0x0)) {
            *(code **)(&DAT_803ae36c + param_1) = param_2;
          }
        }
      }
    }
  }
  FUN_802437a4(uVar2);
  return uVar3;
}

