Toggle = 0
 
if not A_IsAdmin
{
Run *RunAs "%A_ScriptFullPath%"
ExitApp
}
 
Gui,Font,Normal s20 c0xFF0000 Bold,Segoe UI
Gui,Add,Text,x26 y282 w270 h50 Center Right c0xFF0000,
Gui,Font,Normal s16 c0x0,Tahoma
Gui,Add,Text,x104 y70 w350 h50,Lag Switch
Gui,Font
Gui,Add,Button,x110 y130 w90 h50 c0xFF0000,Enable
Gui,Font
Gui,Add,Text,x115 y110 w300 h13,[removed] Em Lag Em
Gui,Show,x933 y315 w310 h290 ,
Gui,Font,Normal Bold,Segoe UI
Gui,Add,Text,X130 Y200 w300 h13, Set Time
Gui,add,Slider, x0 y230 w310 ToolTip TickInterval1 Line2 Range1-10 vTimer2 gLagSlide
Gui, Add, Text, vMsVar, ms
Return
GuiClose:
ExitApp
Return
 
LagSlide:
Timer2 := Timer2*1000
GuiControl, Text, MsVar , %Timer2%
GuiControl, Move, MsVar, W300
return
 
Toggle := 0
 
 
~F2::
if (Toggle){
goto, Timer1
}
 
soundbeep, 523, 130
Toggle := 1
run, netsh advfirewall firewall set rule name="Lagger" new enable=yes,, hide
GuiControl, disable, Enable
SetTimer, Timer1, %Timer2%
return
 
Timer1:
soundbeep 223, 120
Toggle := 0
run, netsh advfirewall firewall set rule name="Lagger" new enable=no,, hide
GuiControl, enable, Enable
SetTimer, Timer1, Off
return
 
 
 
 
end::
Toggle := !toggle
if (Toggle){
soundbeep, 150, 160
ExitApp
return
}