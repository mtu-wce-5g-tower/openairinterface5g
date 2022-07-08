import { FormControl, FormGroup } from '@angular/forms';
import { IInfo } from '../api/commands.api';
import { IArgType } from '../api/commands.api';

const enum VariablesFCN {
  name = 'name',
  value = "value",
  type = "type",
  modifiable = "modifiable"
}


export class VarCtrl extends FormGroup {
  type: IArgType;
  constructor(ivar: IInfo) {
    super({});
    this.type = ivar.type;
    this.addControl(VariablesFCN.name, new FormControl(ivar.name));
    this.addControl(VariablesFCN.value, new FormControl(ivar.value));
    this.addControl(VariablesFCN.type, new FormControl(ivar.type));
    this.addControl(VariablesFCN.modifiable, new FormControl(ivar.modifiable));
  }

  api() {
    const doc: IInfo = {
      name: this.nameFC.value,
      value: String(this.valueFC.value),  //FIXME 
      type: this.typeFC.value,
      modifiable: this.modifiableFC.value
    };

    return doc;
  }

  get nameFC() {
    return this.get(VariablesFCN.name) as FormControl;
  }

  set nameFC(control: FormControl) {
    this.setControl(VariablesFCN.name, control);
  }

  get valueFC() {
    return this.get(VariablesFCN.value) as FormControl;
  }

  set valueFC(control: FormControl) {
    this.setControl(VariablesFCN.value, control);
  }

  get typeFC() {
    return this.get(VariablesFCN.type) as FormControl;
  }

  set typeFC(control: FormControl) {
    this.setControl(VariablesFCN.type, control);
  }

  get modifiableFC() {
    return this.get(VariablesFCN.modifiable) as FormControl;
  }

  set modifiableFC(control: FormControl) {
    this.setControl(VariablesFCN.modifiable, control);
  }

  get btnTxtFC() {
    if (this.type != IArgType.configfile)
      return "set"
    else
      return "download"
  }
}
