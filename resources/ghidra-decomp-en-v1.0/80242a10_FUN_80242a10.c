// Function: FUN_80242a10
// Entry: 80242a10
// Size: 512 bytes

void FUN_80242a10(byte param_1,int param_2,undefined4 param_3,undefined4 param_4)

{
  undefined2 uVar1;
  undefined2 uVar2;
  undefined4 uVar3;
  undefined8 uVar4;
  
  if ((*(uint *)(param_2 + 0x19c) & 2) == 0) {
    FUN_8007d6dc(s_Non_recoverable_Exception__d_8032ca04,param_1);
  }
  else {
    if (*(code **)(&DAT_803ad370 + (uint)param_1 * 4) != (code *)0x0) {
      FUN_80245d94();
      (**(code **)(&DAT_803ad370 + (uint)param_1 * 4))(param_1,param_2,param_3,param_4);
      FUN_80245dd4();
      FUN_80246278();
      FUN_80242394(param_2);
    }
    if (param_1 == 8) {
      FUN_80242394(param_2);
    }
    FUN_8007d6dc(s_Unhandled_Exception__d_8032ca24,param_1);
  }
  FUN_8007d6dc(&DAT_803dc540);
  FUN_80242554(param_2);
  FUN_8007d6dc(s__DSISR___0x_08x_DAR___0x_08x_8032ca3c,param_3,param_4);
  uVar4 = FUN_80246c50();
  FUN_8007d6dc(s_TB___0x_016llx_8032ca70,(int)uVar4,(int)((ulonglong)uVar4 >> 0x20),(int)uVar4);
  switch(param_1) {
  case 2:
    FUN_8007d6dc(s__Instruction_at_0x_x__read_from_S_8032ca80,*(undefined4 *)(param_2 + 0x198),
                 param_4);
    break;
  case 3:
    FUN_8007d6dc(s__Attempted_to_fetch_instruction_f_8032cae0,*(undefined4 *)(param_2 + 0x198));
    break;
  case 5:
    FUN_8007d6dc(s__Instruction_at_0x_x__read_from_S_8032cb2c,*(undefined4 *)(param_2 + 0x198),
                 param_4);
    break;
  case 6:
    FUN_8007d6dc(s__Program_exception___Possible_il_8032cb90,*(undefined4 *)(param_2 + 0x198),
                 param_4);
    break;
  case 0xf:
    FUN_8007d6dc(&DAT_803dc540);
    uVar1 = read_volatile_2(DAT_cc005030);
    uVar2 = read_volatile_2(DAT_cc005032);
    FUN_8007d6dc(s_AI_DMA_Address___0x_04x_04x_8032cbf0,uVar1,uVar2);
    uVar1 = read_volatile_2(DAT_cc005020);
    uVar2 = read_volatile_2(DAT_cc005022);
    FUN_8007d6dc(s_ARAM_DMA_Address___0x_04x_04x_8032cc10,uVar1,uVar2);
    uVar3 = read_volatile_4(DAT_cc006014);
    FUN_8007d6dc(s_DI_DMA_Address___0x_08x_8032cc30,uVar3);
  }
  FUN_8007d6dc(s__Last_interrupt___d___SRR0___0x__8032cc4c,(int)DAT_803dde40,DAT_803dde3c);
  FUN_80294648();
  return;
}

