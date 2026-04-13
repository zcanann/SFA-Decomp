// Function: FUN_8028e724
// Entry: 8028e724
// Size: 832 bytes

void FUN_8028e724(undefined4 *param_1,ushort param_2)

{
  undefined auStack_c8 [44];
  undefined auStack_9c [44];
  undefined4 local_70;
  undefined4 local_6c;
  undefined4 local_68;
  undefined4 local_64;
  undefined4 local_60;
  undefined4 local_5c;
  undefined4 local_58;
  undefined4 local_54;
  undefined4 local_50;
  undefined4 local_4c;
  undefined2 local_48;
  undefined4 auStack_44 [14];
  
  switch(param_2) {
  case 0:
    FUN_8028ea64((undefined *)param_1,&DAT_802c325c,0);
    break;
  case 1:
    FUN_8028ea64((undefined *)param_1,&DAT_802c325e,0);
    break;
  case 2:
    FUN_8028ea64((undefined *)param_1,&DAT_802c3260,0);
    break;
  case 3:
    FUN_8028ea64((undefined *)param_1,&DAT_802c3262,0);
    break;
  case 4:
    FUN_8028ea64((undefined *)param_1,&DAT_802c3264,1);
    break;
  case 5:
    FUN_8028ea64((undefined *)param_1,&DAT_802c3267,1);
    break;
  case 6:
    FUN_8028ea64((undefined *)param_1,&DAT_802c326a,1);
    break;
  case 7:
    FUN_8028ea64((undefined *)param_1,&DAT_802c326d,2);
    break;
  case 8:
    FUN_8028ea64((undefined *)param_1,&DAT_802c3271,2);
    break;
  case 0xffffffc0:
    FUN_8028ea64((undefined *)param_1,s_54210108624275221700372640043497_802c31bd,0xffec);
    break;
  default:
    FUN_8028e724(auStack_44,(short)param_2 / 2);
    FUN_8028eb50((undefined *)param_1,(int)auStack_44,(int)auStack_44);
    if ((param_2 & 1) != 0) {
      local_70 = *param_1;
      local_6c = param_1[1];
      local_68 = param_1[2];
      local_64 = param_1[3];
      local_60 = param_1[4];
      local_5c = param_1[5];
      local_58 = param_1[6];
      local_54 = param_1[7];
      local_50 = param_1[8];
      local_4c = param_1[9];
      local_48 = *(undefined2 *)(param_1 + 10);
      if ((short)param_2 < 1) {
        FUN_8028ea64(auStack_c8,&DAT_802c325a,0xffff);
        FUN_8028eb50((undefined *)param_1,(int)&local_70,(int)auStack_c8);
      }
      else {
        FUN_8028ea64(auStack_9c,&DAT_802c325e,0);
        FUN_8028eb50((undefined *)param_1,(int)&local_70,(int)auStack_9c);
      }
    }
    break;
  case 0xffffffcb:
    FUN_8028ea64((undefined *)param_1,s_11102230246251565404236316680908_802c31eb,0xfff0);
    break;
  case 0xffffffe0:
    FUN_8028ea64((undefined *)param_1,s_23283064365386962890625_802c3212,0xfff6);
    break;
  case 0xfffffff0:
    FUN_8028ea64((undefined *)param_1,s_152587890625_802c322a,0xfffb);
    break;
  case 0xfffffff8:
    FUN_8028ea64((undefined *)param_1,s_390625_802c3237,0xfffd);
    break;
  case 0xfffffff9:
    FUN_8028ea64((undefined *)param_1,s_78125_802c323e,0xfffd);
    break;
  case 0xfffffffa:
    FUN_8028ea64((undefined *)param_1,s_15625_802c3244,0xfffe);
    break;
  case 0xfffffffb:
    FUN_8028ea64((undefined *)param_1,&DAT_802c324a,0xfffe);
    break;
  case 0xfffffffc:
    FUN_8028ea64((undefined *)param_1,&DAT_802c324f,0xfffe);
    break;
  case 0xfffffffd:
    FUN_8028ea64((undefined *)param_1,&DAT_802c3253,0xffff);
    break;
  case 0xfffffffe:
    FUN_8028ea64((undefined *)param_1,&DAT_802c3257,0xffff);
    break;
  case 0xffffffff:
    FUN_8028ea64((undefined *)param_1,&DAT_802c325a,0xffff);
  }
  return;
}

