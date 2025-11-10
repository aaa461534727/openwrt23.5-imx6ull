datconf -f /tmp/cste/temp_status set wan_speed $SPEED
if [ "$PORT" = "0" ]; then
	if [ "DOWN" = "$ACTION" ];then
           	lktos_reload wan_port_down
      	fi
fi

