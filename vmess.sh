#!/bin/bash

red='\e[91m'
green='\e[92m'
yellow='\e[93m'
magenta='\e[95m'
cyan='\e[96m'
none='\e[0m'

# Root
[[ $(id -u) != 0 ]] && echo -e " Ups ... silakan gunakan ${red}root ${none} Jalankan pengguna ${yellow}~(^_^) ${none}" && exit 1

_version="v2.33"

cmd="apt-get"

sys_bit=$(uname -m)

if [[ $sys_bit == "i386" || $sys_bit == "i686" ]]; then
	v2ray_bit="32"
elif [[ $sys_bit == "x86_64" ]]; then
	v2ray_bit="64"
else
	echo -e " Haha ... ini ${red} Naskah ayam pedas ${none} Tidak mendukung sistem Anda。 ${yellow}(-_-) ${none}" && exit 1
fi

# Metode deteksi bodoh
if [[ -f /usr/bin/apt-get ]] || [[ -f /usr/bin/yum && -f /bin/systemctl ]]; then

	if [[ -f /usr/bin/yum ]]; then

		cmd="yum"

	fi
	if [[ -f /bin/systemctl ]]; then
		systemd=true
	fi

else

	echo -e " Haha ... ini ${red} Naskah ayam pedas ${none} Tidak mendukung sistem Anda ${yellow}(-_-) ${none}" && exit 1

fi

backup="/etc/v2ray/233blog_v2ray_backup.conf"

if [[ -f /usr/bin/v2ray/v2ray && -f /etc/v2ray/config.json ]] && [[ -f $backup && -d /etc/v2ray/233boy/v2ray ]]; then

	. $backup
	v2ray_ver=$(/usr/bin/v2ray/v2ray -version | head -n 1 | cut -d " " -f2)
	if [[ ! $username ]]; then
		. /etc/v2ray/233boy/v2ray/tools/support_socks.sh
	fi

elif [[ -f /usr/bin/v2ray/v2ray && -f /etc/v2ray/config.json ]] && [[ -f /etc/v2ray/233blog_v2ray_backup.txt && -d /etc/v2ray/233boy/v2ray ]]; then

	. /etc/v2ray/233boy/v2ray/tools/v1xx_to_v2xx.sh

else
	echo -e " astaga …… ${red} Ada yang salah ... Harap instal ulang V2Ray ${none} ${yellow}~(^_^) ${none}" && exit 1
fi

if [[ $caddy_status ]]; then
	caddy_installed=true
fi
if [[ $shadowsocks_status ]]; then
	shadowsocks=true
fi
if [[ $blocked_ad_status ]]; then
	is_blocked_ad=true
fi
if [[ $v2ray_transport -ge 9 && $v2ray_transport -le 15 ]]; then
	dynamicPort=true
	port_range="${v2ray_dynamicPort_start}-${v2ray_dynamicPort_end}"
fi
if [[ $path_status ]]; then
	is_path=true
fi

uuid=$(cat /proc/sys/kernel/random/uuid)
old_id="23332333-2333-2333-2333-233boy233boy"
v2ray_server_config="/etc/v2ray/config.json"
v2ray_client_config="/etc/v2ray/233blog_v2ray_config.json"
v2ray_pid=$(ps ux | grep "/usr/bin/v2ray/v2ray" | grep -v grep | awk '{print $2}')
caddy_pid=$(pgrep "caddy")

if [ $v2ray_pid ]; then
	v2ray_status="$green Bejalan $none"
else
	v2ray_status="$red Tiak Berjalan $none"
fi
if [[ $v2ray_transport == "4" && $caddy_installed ]] && [[ $caddy_pid ]]; then
	caddy_run_status="$green Berjalan $none"
else
	caddy_run_status="$red Tidak Berjalan $none"
fi

transport=(
	TCP
	TCP_HTTP
	WebSocket
	"WebSocket + TLS"
	mKCP
	mKCP_utp
	mKCP_srtp
	mKCP_wechat-video
	TCP_dynamicPort
	TCP_HTTP_dynamicPort
	WebSocket_dynamicPort
	mKCP_dynamicPort
	mKCP_utp_dynamicPort
	mKCP_srtp_dynamicPort
	mKCP_wechat-video_dynamicPort
	HTTP/2
	Socks5
)

ciphers=(
	aes-128-cfb
	aes-256-cfb
	chacha20
	chacha20-ietf
	aes-128-gcm
	aes-256-gcm
	chacha20-ietf-poly1305
)

get_transport_args() {
	header="none"
	if [[ $is_path ]]; then
		_path="/$path"
	else
		_path="/"
	fi
	case $v2ray_transport in
	1 | 9)
		net="tcp"
		;;
	2 | 10)
		net="tcp"
		header="http"
		host="www.baidu.com"
		;;
	3 | 4 | 11)
		net="ws"
		;;
	5 | 12)
		net="kcp"
		;;
	6 | 13)
		net="kcp"
		header="utp"
		;;
	7 | 14)
		net="kcp"
		header="srtp"
		;;
	8 | 15)
		net="kcp"
		header="wechat-video"
		;;
	16)
		net="h2"
		;;
	esac
}
create_vmess_URL_config() {

	[[ -z $net ]] && get_transport_args

	if [[ $v2ray_transport == "4" || $v2ray_transport == 16 ]]; then
		cat >/etc/v2ray/vmess_qr.json <<-EOF
		{
			"v": "2",
			"ps": "233blog_v2ray_${domain}",
			"add": "${domain}",
			"port": "443",
			"id": "${v2ray_id}",
			"aid": "${alterId}",
			"net": "${net}",
			"type": "none",
			"host": "${domain}",
			"path": "$_path",
			"tls": "tls"
		}
		EOF
	else
		[[ -z $ip ]] && get_ip
		cat >/etc/v2ray/vmess_qr.json <<-EOF
		{
			"v": "2",
			"ps": "233blog_v2ray_${ip}",
			"add": "${ip}",
			"port": "${v2ray_port}",
			"id": "${v2ray_id}",
			"aid": "${alterId}",
			"net": "${net}",
			"type": "${header}",
			"host": "${host}",
			"path": "",
			"tls": ""
		}
		EOF
	fi
}
view_v2ray_config_info() {

	[[ $v2ray_transport != 17 ]] && get_transport_args
	[[ -z $ip ]] && get_ip
	echo
	echo
	echo "---------- Informasi konfigurasi V2Ray -------------"
	if [[ $v2ray_transport == "4" || $v2ray_transport == 16 ]]; then
		if [[ ! $caddy_installed ]]; then
			echo
			echo -e " $red peringatan！$none$yellow Silakan konfigurasikan sendiri TLS...Tutorial: https://233blog.com/post/19/$none"
		fi
		echo
		echo -e "$yellow Host (Address) = $cyan${domain}$none"
		echo
		echo -e "$yellow Port (Port) = ${cyan}443${none}"
		echo
		echo -e "$yellow identitas pengguna (User ID / UUID) = $cyan${v2ray_id}$none"
		echo
		echo -e "$yellow ID ekstra (Alter Id) = ${cyan}${alterId}${none}"
		echo
		echo -e "$yellow Protokol Transfer (Network) = ${cyan}${net}$none"
		echo
		echo -e "$yellow Jenis kamuflase (header type) = ${cyan}${header}$none"
		echo
		echo -e "$yellow Nama domain palsu (host) = ${cyan}${domain}$none"
		echo
		echo -e "$yellow Jalur jalan (path) = ${cyan}${_path}$none"
		echo
		echo -e "$yellow TLS (Enable TLS) = ${cyan}打开$none"
		echo
		if [[ $is_blocked_ad ]]; then
			echo " Catatan: Pemblokiran iklan diaktifkan.."
			echo
		fi
	elif [[ $v2ray_transport == 17 ]]; then
		echo
		echo -e "$yellow Host (Hostname) = $cyan${ip}$none"
		echo
		echo -e "$yellow Port (Port) = $cyan$v2ray_port$none"
		echo
		echo -e "$yellow Username (Username) = $cyan${username}$none"
		echo
		echo -e "$yellow Password (Password) = $cyan${userpass}$none"
		echo
		echo -e "$yellow Telegram Tautan konfigurasi agen = ${cyan}tg://socks?server=${ip}&port=${v2ray_port}&user=${username}&pass=${userpass}$none"
		echo
		echo " Ini adalah konfigurasi yang terkait dengan protokol Socks5 ... Tidak peduli dengan beberapa klien V2Ray, mengapa mereka tidak memiliki konfigurasi Dongdong ini"
		echo
	else
		echo
		echo -e "$yellow Alamat (Address) = $cyan${ip}$none"
		echo
		echo -e "$yellow Port (Port) = $cyan$v2ray_port$none"
		echo
		echo -e "$yellow identitas pengguna (User ID / UUID) = $cyan${v2ray_id}$none"
		echo
		echo -e "$yellow ID ekstra (Alter Id) = ${cyan}${alterId}${none}"
		echo
		echo -e "$yellow Protokol Transfer (Network) = ${cyan}${net}$none"
		echo
		echo -e "$yellow Jenis kamuflase (header type) = ${cyan}${header}$none"
		echo
	fi
	if [[ $v2ray_transport -ge 9 && $v2ray_transport -le 15 ]] && [[ $is_blocked_ad ]]; then
		echo " Catatan: Port dinamis diaktifkan ... Pemblokiran iklan diaktifkan..."
		echo
	elif [[ $v2ray_transport -ge 9 && $v2ray_transport -le 15 ]]; then
		echo " Catatan: Port dinamis diaktifkan..."
		echo
	elif [[ $is_blocked_ad ]]; then
		echo " Catatan: Pemblokiran iklan diaktifkan.."
		echo
	fi
	echo "---------- END -------------"
	echo
	echo "VTutorial klien 2Ray: https://233blog.com/post/20/"
	echo
}
get_shadowsocks_config() {
	if [[ $shadowsocks ]]; then

		while :; do
			echo
			echo -e "$yellow 1. $none Lihat informasi konfigurasi Shadowsocks"
			echo
			echo -e "$yellow 2. $none Buat tautan kode QR"
			echo
			read -p "$(echo -e "tolong pilih [${magenta}1-2$none]:")" _opt
			if [[ -z $_opt ]]; then
				error
			else
				case $_opt in
				1)
					view_shadowsocks_config_info
					break
					;;
				2)
					get_shadowsocks_config_qr_link
					break
					;;
				*)
					error
					;;
				esac
			fi

		done
	else
		shadowsocks_config
	fi
}
view_shadowsocks_config_info() {
	if [[ $shadowsocks ]]; then
		get_ip
		local ss="ss://$(echo -n "${ssciphers}:${sspass}@${ip}:${ssport}" | base64 -w 0)#233blog_ss_${ip}"
		echo
		echo
		echo "---------- Informasi konfigurasi Shadowsocks -------------"
		echo
		echo -e "$yellow alamat server = $cyan${ip}$none"
		echo
		echo -e "$yellow Port server = $cyan$ssport$none"
		echo
		echo -e "$yellow Kata sandi = $cyan$sspass$none"
		echo
		echo -e "$yellow Protokol enkripsi = $cyan${ssciphers}$none"
		echo
		echo -e "$yellow Tautan SS = ${cyan}$ss$none"
		echo
		echo -e " Catatan:$red Shadowsocks Win 4.0.6 $none Klien mungkin tidak mengenali tautan SS"
		echo
	else
		shadowsocks_config
	fi
}
get_shadowsocks_config_qr_link() {
	if [[ $shadowsocks ]]; then
		echo
		echo -e "$green Menghasilkan link .... Tunggu sebentar.....$none"
		echo
		get_ip
		local ss="ss://$(echo -n "${ssciphers}:${sspass}@${ip}:${ssport}" | base64 -w 0)#233blog_ss_${ip}"
		echo "${ss}" >/tmp/233blog_shadowsocks.txt
		cat /tmp/233blog_shadowsocks.txt | qrencode -s 50 -o /tmp/233blog_shadowsocks.png

		local random=$(echo $RANDOM-$RANDOM-$RANDOM | base64 -w 0)
		local link=$(curl -s --upload-file /tmp/233blog_shadowsocks.png "https://transfer.sh/${random}_233blog_shadowsocks.png")
		if [[ $link ]]; then
			echo
			echo "---------- Tautan kode QR Shadowsocks -------------"
			echo
			echo -e "$yellow tautan = $cyan$link$none"
			echo
			echo -e " Tips...$red Shadowsocks Win 4.0.6 $none Klien mungkin tidak mengenali kode QR"
			echo
			echo "Catatan ... tautan akan kedaluwarsa dalam 14 hari"
			echo
			echo "Pengingat ... tolong jangan bagikan tautan ... kecuali Anda punya alasan khusus...."
			echo
		else
			echo
			echo -e "$red Ups ... ada yang tidak beres ... coba lagi $none"
			echo
		fi
		rm -rf /tmp/233blog_shadowsocks.png
		rm -rf /tmp/233blog_shadowsocks.txt
	else
		shadowsocks_config
	fi

}

get_shadowsocks_config_qr_ask() {
	echo
	while :; do
		echo -e "Perlu menghasilkan $yellow Informasi konfigurasi Shadowsocks $none Tautan kode QR [${magenta}Y/N$none]"
		read -p "$(echo -e "default [${magenta}N$none]:")" y_n
		[ -z $y_n ] && y_n="n"
		if [[ $y_n == [Yy] ]]; then
			get_shadowsocks_config_qr_link
			break
		elif [[ $y_n == [Nn] ]]; then
			break
		else
			error
		fi
	done

}
change_shadowsocks_config() {
	if [[ $shadowsocks ]]; then

		while :; do
			echo
			echo -e "$yellow 1. $none Ubah port Shadowsocks"
			echo
			echo -e "$yellow 2. $none Ubah kata sandi Shadowsocks"
			echo
			echo -e "$yellow 3. $none Ubah protokol enkripsi Shadowsocks"
			echo
			echo -e "$yellow 4. $none Tutup Shadowsocks"
			echo
			read -p "$(echo -e "tolong pilih [${magenta}1-4$none]:")" _opt
			if [[ -z $_opt ]]; then
				error
			else
				case $_opt in
				1)
					change_shadowsocks_port
					break
					;;
				2)
					change_shadowsocks_password
					break
					;;
				3)
					change_shadowsocks_ciphers
					break
					;;
				4)
					disable_shadowsocks
					break
					;;
				*)
					error
					;;
				esac
			fi

		done
	else

		shadowsocks_config
	fi
}
shadowsocks_config() {
	echo
	echo
	echo -e " $red Bos ... Anda tidak mengkonfigurasi Shadowsocks $none...Tetapi jika Anda ingin mengkonfigurasinya sekarang, Anda bisa ^_^"
	echo
	echo

	while :; do
		echo -e "Apakah akan mengonfigurasi ${yellow}Shadowsocks${none} [${magenta}Y/N$none]"
		read -p "$(echo -e "(default [${cyan}N$none]):") " install_shadowsocks
		[[ -z "$install_shadowsocks" ]] && install_shadowsocks="n"
		if [[ "$install_shadowsocks" == [Yy] ]]; then
			echo
			shadowsocks=true
			shadowsocks_port_config
			shadowsocks_password_config
			shadowsocks_ciphers_config
			pause
			open_port $new_ssport
			backup_config +ss
			ssport=$new_ssport
			sspass=$new_sspass
			ssciphers=$new_ssciphers
			config
			clear
			view_shadowsocks_config_info
			get_shadowsocks_config_qr_ask
			break
		elif [[ "$install_shadowsocks" == [Nn] ]]; then
			echo
			echo -e " $green Belum dikonfigurasi Shadowsocks ....$none"
			echo
			break
		else
			error
		fi

	done
}
shadowsocks_port_config() {
	local random=$(shuf -i20001-65535 -n1)
	while :; do
		echo -e "silahkan masuk "$yellow"Shadowsocks"$none" Pelabuhan ["$magenta"1-65535"$none"]，Tidak bisa dan "$yellow"V2ray"$none" Port yang sama"
		read -p "$(echo -e "(Port default: ${cyan}${random}$none):") " new_ssport
		[ -z "$new_ssport" ] && new_ssport=$random
		case $new_ssport in
		$v2ray_port)
			echo
			echo -e " Tidak bisa dan $cyan Port V2Ray $none Sama...."
			error
			;;
		[1-9] | [1-9][0-9] | [1-9][0-9][0-9] | [1-9][0-9][0-9][0-9] | [1-5][0-9][0-9][0-9][0-9] | 6[0-4][0-9][0-9][0-9] | 65[0-4][0-9][0-9] | 655[0-3][0-5])
			if [[ $v2ray_transport == "4" || $v2ray_transport == "16" ]]; then
				local tls=ture
			fi
			if [[ $tls && $new_ssport == "80" ]] || [[ $tls && $new_ssport == "443" ]]; then
				echo
				echo -e "Karena Anda sedang menggunakan "$green"WebSocket + TLS $none atau $green HTTP/2"$none" Protokol Transfer."
				echo
				echo -e "Jadi tidak bisa memilih "$magenta"80"$none" atau "$magenta"443"$none" Pelabuhan"
				error
			elif [[ $dynamicPort ]] && [[ $v2ray_dynamicPort_start == $new_ssport || $v2ray_dynamicPort_end == $new_ssport ]]; then
				local multi_port="${v2ray_dynamicPort_start} - ${v2ray_dynamicPort_end}"
				echo
				echo -e " Maaf ... pelabuhan ini dan $yellow Port dinamis V2Ray $none Konflik ... Rentang port dinamis V2Ray saat ini adalah: $cyan$multi_port$none"
				error
			elif [[ $dynamicPort ]] && [[ $v2ray_dynamicPort_start -lt $new_ssport && $new_ssport -le $v2ray_dynamicPort_end ]]; then
				local multi_port="${v2ray_dynamicPort_start} - ${v2ray_dynamicPort_end}"
				echo
				echo -e " Maaf ... pelabuhan ini dan $yellow Port dinamis V2Ray $none Konflik ... Rentang port dinamis V2Ray saat ini adalah: $cyan$multi_port$none"
				error
			else
				echo
				echo
				echo -e "$yellow Shadowsocks Pelabuhan = $cyan$new_ssport$none"
				echo "----------------------------------------------------------------"
				echo
				break
			fi
			;;
		*)
			error
			;;
		esac

	done

}

shadowsocks_password_config() {

	while :; do
		echo -e "silahkan masuk "$yellow"Shadowsocks"$none" kata sandi"
		read -p "$(echo -e "(kata sandi default: ${cyan}233blog.com$none)"): " new_sspass
		[ -z "$new_sspass" ] && new_sspass="233blog.com"
		case $new_sspass in
		*[/$]*)
			echo
			echo -e " Karena script ini terlalu pedas ... jadi kata sandinya tidak bisa dimasukkan $red / $none atau $red $ $none Dua simbol ini.... "
			echo
			error
			;;
		*)
			echo
			echo
			echo -e "$yellow Kata sandi Shadowsocks = $cyan$new_sspass$none"
			echo "----------------------------------------------------------------"
			echo
			break
			;;
		esac

	done

}

shadowsocks_ciphers_config() {

	while :; do
		echo -e "tolong pilih "$yellow"Shadowsocks"$none" Protokol enkripsi [${magenta}1-7$none]"
		for ((i = 1; i <= ${#ciphers[*]}; i++)); do
			ciphers_show="${ciphers[$i - 1]}"
			echo
			echo -e "$yellow $i. $none${ciphers_show}"
		done
		echo
		read -p "$(echo -e "(Protokol enkripsi default: ${cyan}${ciphers[6]}$none)"):" ssciphers_opt
		[ -z "$ssciphers_opt" ] && ssciphers_opt=7
		case $ssciphers_opt in
		[1-7])
			new_ssciphers=${ciphers[$ssciphers_opt - 1]}
			echo
			echo
			echo -e "$yellow Protokol enkripsi Shadowsocks = $cyan${new_ssciphers}$none"
			echo "----------------------------------------------------------------"
			echo
			break
			;;
		*)
			error
			;;
		esac

	done
}

change_shadowsocks_port() {
	echo
	while :; do
		echo -e "silahkan masuk "$yellow"Shadowsocks"$none" Pelabuhan ["$magenta"1-65535"$none"]"
		read -p "$(echo -e "(Porta saat ini: ${cyan}$ssport$none):") " new_ssport
		[ -z "$new_ssport" ] && error && continue
		case $new_ssport in
		$ssport)
			echo
			echo " Ini sama dengan port saat ini ... Ubahlah"
			error
			;;
		$v2ray_port)
			echo
			echo -e " Tidak bisa dan $cyan Port V2Ray $none Sama...."
			error
			;;
		[1-9] | [1-9][0-9] | [1-9][0-9][0-9] | [1-9][0-9][0-9][0-9] | [1-5][0-9][0-9][0-9][0-9] | 6[0-4][0-9][0-9][0-9] | 65[0-4][0-9][0-9] | 655[0-3][0-5])
			if [[ $v2ray_transport == "4" || $v2ray_transport == "16" ]]; then
				local tls=ture
			fi
			if [[ $tls && $new_ssport == "80" ]] || [[ $tls && $new_ssport == "443" ]]; then
				echo
				echo -e "Karena Anda sedang menggunakan "$green"WebSocket + TLS $none atau $green HTTP/2"$none" Protokol Transfer."
				echo
				echo -e "Jadi tidak bisa memilih "$magenta"80"$none" atau "$magenta"443"$none" Pelabuhan"
				error
			elif [[ $dynamicPort ]] && [[ $v2ray_dynamicPort_start == $new_ssport || $v2ray_dynamicPort_end == $new_ssport ]]; then
				local multi_port="${v2ray_dynamicPort_start} - ${v2ray_dynamicPort_end}"
				echo
				echo -e " Maaf ... pelabuhan ini dan $yellow Port dinamis V2Ray $none Konflik ... Rentang port dinamis V2Ray saat ini adalah: $cyan$multi_port$none"
				error
			elif [[ $dynamicPort ]] && [[ $v2ray_dynamicPort_start -lt $new_ssport && $new_ssport -le $v2ray_dynamicPort_end ]]; then
				local multi_port="${v2ray_dynamicPort_start} - ${v2ray_dynamicPort_end}"
				echo
				echo -e " Maaf ... pelabuhan ini dan $yellow Port dinamis V2Ray $none Konflik ... Rentang port dinamis V2Ray saat ini adalah: $cyan$multi_port$none"
				error
			else
				echo
				echo
				echo -e "$yellow Pelabuhan Shadowsocks = $cyan$new_ssport$none"
				echo "----------------------------------------------------------------"
				echo
				pause
				# sed -i "45s/=$ssport/=$new_ssport/" $backup
				backup_config ssport
				del_port $ssport
				open_port $new_ssport
				ssport=$new_ssport
				config
				clear
				view_shadowsocks_config_info
				get_shadowsocks_config_qr_ask
				break
			fi
			;;
		*)
			error
			;;
		esac

	done
}
change_shadowsocks_password() {
	echo
	while :; do
		echo -e "silahkan masuk "$yellow"Shadowsocks"$none" kata sandi"
		read -p "$(echo -e "(kata sandi saat ini：${cyan}$sspass$none)"): " new_sspass
		[ -z "$new_sspass" ] && error && continue
		case $new_sspass in
		$sspass)
			echo
			echo " Sama seperti kata sandi saat ini ... ubahlah"
			error
			;;
		*[/$]*)
			echo
			echo -e " Karena script ini terlalu pedas ... jadi kata sandinya tidak bisa dimasukkan $red / $none atau $red $ $none Dua simbol ini.... "
			echo
			error
			;;
		*)
			echo
			echo
			echo -e "$yellow Kata sandi Shadowsocks = $cyan$new_sspass$none"
			echo "----------------------------------------------------------------"
			echo
			pause
			# sed -i "48s/=$sspass/=$new_sspass/" $backup
			backup_config sspass
			sspass=$new_sspass
			config
			clear
			view_shadowsocks_config_info
			get_shadowsocks_config_qr_ask
			break
			;;
		esac

	done

}

change_shadowsocks_ciphers() {
	echo
	while :; do
		echo -e "tolong pilih "$yellow"Shadowsocks"$none" Protokol enkripsi [${magenta}1-${#ciphers[*]}$none]"
		for ((i = 1; i <= ${#ciphers[*]}; i++)); do
			ciphers_show="${ciphers[$i - 1]}"
			echo
			echo -e "$yellow $i. $none${ciphers_show}"
		done
		echo
		read -p "$(echo -e "(Protokol enkripsi saat ini: ${cyan}${ssciphers}$none)"):" ssciphers_opt
		[ -z "$ssciphers_opt" ] && error && continue
		case $ssciphers_opt in
		[1-7])
			new_ssciphers=${ciphers[$ssciphers_opt - 1]}
			if [[ $new_ssciphers == $ssciphers ]]; then
				echo
				echo " Ini sama dengan protokol enkripsi saat ini ..."
				error && continue
			fi
			echo
			echo
			echo -e "$yellow Protokol enkripsi Shadowsocks = $cyan${new_ssciphers}$none"
			echo "----------------------------------------------------------------"
			echo
			pause
			# sed -i "51s/=$ssciphers/=$new_ssciphers/" $backup
			backup_config ssciphers
			ssciphers=$new_ssciphers
			config
			clear
			view_shadowsocks_config_info
			get_shadowsocks_config_qr_ask
			break
			;;
		*)
			error
			;;
		esac

	done

}
disable_shadowsocks() {
	echo

	while :; do
		echo -e "Apakah akan ditutup ${yellow}Shadowsocks${none} [${magenta}Y/N$none]"
		read -p "$(echo -e "(default [${cyan}N$none]):") " y_n
		[[ -z "$y_n" ]] && y_n="n"
		if [[ "$y_n" == [Yy] ]]; then
			echo
			echo
			echo -e "$yellow Tutup Shadowsocks = $cyan Ya $none"
			echo "----------------------------------------------------------------"
			echo
			pause
			# sed -i "31s/true/false/" $backup
			backup_config -ss
			del_port $ssport
			shadowsocks=''
			config
			# clear
			echo
			echo
			echo
			echo -e "$green Shadowsocks dimatikan ... tetapi Anda dapat mengaktifkan kembali Shadowsocks kapan saja ... selama Anda mau $none"
			echo
			break
		elif [[ "$y_n" == [Nn] ]]; then
			echo
			echo -e " $green Shadowsocks telah dibatalkan ....$none"
			echo
			break
		else
			error
		fi

	done
}
change_v2ray_config() {
	local _menu=(
		"Ubah port V2Ray"
		"Ubah protokol transmisi V2Ray"
		"Ubah port dinamis V2Ray (jika memungkinkan)"
		"Ubah ID Pengguna (UUID )"
		"Ubah nama domain TLS (jika memungkinkan)"
		"Ubah jalur pengalihan (jika memungkinkan)"
		"Ubah URL yang disamarkan (jika memungkinkan)"
		"Matikan kamuflase situs dan pengalihan jalur (jika memungkinkan)"
		"Aktifkan / nonaktifkan pemblokiran iklan"
		"Ubah nama pengguna Socks5 (jika memungkinkan)"
		"Ubah kata sandi Socks5 (jika memungkinkan)"
	)
	while :; do
		for ((i = 1; i <= ${#_menu[*]}; i++)); do
			if [[ "$i" -le 9 ]]; then
				echo
				echo -e "$yellow  $i. $none${_menu[$i - 1]}"
			else
				echo
				echo -e "$yellow $i. $none${_menu[$i - 1]}"
			fi
		done
		echo
		read -p "$(echo -e "tolong pilih [${magenta}1-${#_menu[*]}$none]:")" _opt
		if [[ -z $_opt ]]; then
			error
		else
			case $_opt in
			1)
				change_v2ray_port
				break
				;;
			2)
				change_v2ray_transport
				break
				;;
			3)
				change_v2ray_dynamicport
				break
				;;
			4)
				change_v2ray_id
				break
				;;
			5)
				change_domain
				break
				;;
			6)
				change_path_config
				break
				;;
			7)
				change_proxy_site_config
				break
				;;
			8)
				disable_path
				break
				;;
			9)
				blocked_hosts
				break
				;;
			10)
				change_socks_user_config
				break
				;;
			11)
				change_socks_pass_config
				break
				;;
			[aA][Ii][aA][Ii] | [Dd][Dd])
				socks_check
				custom_uuid
				break
				;;
			[Dd] | [Aa][Ii] | 233 | 233[Bb][Ll][Oo][Gg] | 233[Bb][Ll][Oo][Gg].[Cc][Oo][Mm] | 233[Bb][Oo][Yy] | [Aa][Ll][Tt][Ee][Rr][Ii][Dd])
				change_v2ray_alterId
				break
				;;
			*)
				error
				;;
			esac
		fi
	done
}
change_v2ray_port() {
	if [[ $v2ray_transport == 4 ]]; then
		echo
		echo -e " Karena Anda sedang menggunakan $yellow WebSocket + TLS $none Protokol transmisi ... jadi tidak ada perbedaan antara memperbaiki atau memodifikasi port V2Ray"
		echo
		echo " Jika Anda ingin menggunakan port lain ... Anda dapat memodifikasi protokol transmisi V2Ray terlebih dahulu ... kemudian mengubah port V2Ray"
		echo
		change_v2ray_transport_ask
	elif [[ $v2ray_transport == 16 ]]; then
		echo
		echo -e " Karena Anda sedang menggunakan $yellow HTTP/2 $none Protokol transmisi ... jadi tidak ada perbedaan antara memperbaiki atau memodifikasi port V2Ray"
		echo
		echo " Jika Anda ingin menggunakan port lain ... Anda dapat memodifikasi protokol transmisi V2Ray terlebih dahulu ... kemudian mengubah port V2Ray"
		echo
		change_v2ray_transport_ask
	else
		echo
		while :; do
			echo -e "silahkan masuk "$yellow"V2Ray"$none" Pelabuhan ["$magenta"1-65535"$none"]"
			read -p "$(echo -e "(Porta saat ini: ${cyan}${v2ray_port}$none):")" v2ray_port_opt
			[[ -z $v2ray_port_opt ]] && error && continue
			case $v2ray_port_opt in
			$v2ray_port)
				echo
				echo " Oh ... itu sama dengan port saat ini ... Ubahlah"
				error
				;;
			[1-9] | [1-9][0-9] | [1-9][0-9][0-9] | [1-9][0-9][0-9][0-9] | [1-5][0-9][0-9][0-9][0-9] | 6[0-4][0-9][0-9][0-9] | 65[0-4][0-9][0-9] | 655[0-3][0-5])
				if [[ $shadowsocks ]] && [[ $v2ray_port_opt == $ssport ]]; then
					echo
					echo -e " ...Tidak bisa mengikuti $cyan pelabuhan Shadowsocks $none Sama..."
					error
				elif [[ $dynamicPort ]] && [[ $v2ray_dynamicPort_start == $v2ray_port_opt || $v2ray_dynamicPort_end == $v2ray_port_opt ]]; then
					local multi_port="${v2ray_dynamicPort_start} - ${v2ray_dynamicPort_end}"
					echo
					echo -e " Maaf .. port ini dan $yellow Port dinamis V2Ray $none Port dinamis V2Ray: $cyan$multi_port$none"
					error

				elif [[ $dynamicPort ]] && [[ $v2ray_dynamicPort_start -lt $v2ray_port_opt && $v2ray_port_opt -le $v2ray_dynamicPort_end ]]; then
					local multi_port="${v2ray_dynamicPort_start} - ${v2ray_dynamicPort_end}"
					echo
					echo -e " Maaf ... pelabuhan ini dan $yellow Port dinamis V2Ray $none Konflik ... Rentang port dinamis V2Ray saat ini adalah: $cyan$multi_port$none"
					error
				else
					echo
					echo
					echo -e "$yellow Port V2Ray = $cyan$v2ray_port_opt$none"
					echo "----------------------------------------------------------------"
					echo
					pause
					# sed -i "19s/$v2ray_port/$v2ray_port_opt/" $backup
					backup_config v2ray_port
					del_port $v2ray_port
					open_port $v2ray_port_opt
					v2ray_port=$v2ray_port_opt
					config
					clear
					view_v2ray_config_info
					download_v2ray_config_ask
					break
				fi
				;;
			*)
				error
				;;
			esac

		done
	fi

}
download_v2ray_config_ask() {
	echo
	while :; do
		echo -e "Apakah Anda perlu mengunduh konfigurasi V2Ray / membuat tautan informasi konfigurasi / membuat tautan kode QR [${magenta}Y/N$none]"
		read -p "$(echo -e "default [${cyan}N$none]:")" y_n
		[ -z $y_n ] && y_n="n"
		if [[ $y_n == [Yy] ]]; then
			download_v2ray_config
			break
		elif [[ $y_n == [Nn] ]]; then
			break
		else
			error
		fi
	done

}
change_v2ray_transport_ask() {
	echo
	while :; do
		echo -e "Perlu diubah $yellow V2Ray $none Protokol Transfer [${magenta}Y/N$none]"
		read -p "$(echo -e "default [${cyan}N$none]:")" y_n
		[ -z $y_n ] && break
		if [[ $y_n == [Yy] ]]; then
			change_v2ray_transport
			break
		elif [[ $y_n == [Nn] ]]; then
			break
		else
			error
		fi
	done
}
change_v2ray_transport() {
	echo
	while :; do
		echo -e "tolong pilih "$yellow"V2Ray"$none" Protokol Transfer [${magenta}1-${#transport[*]}$none]"
		echo
		for ((i = 1; i <= ${#transport[*]}; i++)); do
			Stream="${transport[$i - 1]}"
			if [[ "$i" -le 9 ]]; then
				# echo
				echo -e "$yellow  $i. $none${Stream}"
			else
				# echo
				echo -e "$yellow $i. $none${Stream}"
			fi
		done
		echo
		echo "Catatan 1: Jika [dynamicPort] disertakan, port dinamis diaktifkan.."
		echo "Catatan 2: [utp | srtp | wechat-video] disamarkan sebagai [BT download | video call | Video call WeChat]"
		echo
		read -p "$(echo -e "(Protokol transfer saat ini: ${cyan}${transport[$v2ray_transport - 1]}$none)"):" v2ray_transport_opt
		if [ -z "$v2ray_transport_opt" ]; then
			error
		else
			case $v2ray_transport_opt in
			$v2ray_transport)
				echo
				echo " Ups ... itu sama dengan protokol transmisi saat ini ... Ubahlah"
				error
				;;
			4 | 16)
				if [[ $v2ray_port == "80" || $v2ray_port == "443" ]]; then
					echo
					echo -e " Maaf ... jika Anda ingin menggunakan ${cyan} ${transport[$v2ray_transport_opt - 1]} $none Protokol Transfer.. ${red}Porta V2Ray tidak boleh 80 atau 443 ...$none"
					echo
					echo -e " Port V2Ray saat ini: ${cyan}$v2ray_port$none"
					error
				elif [[ $shadowsocks ]] && [[ $ssport == "80" || $ssport == "443" ]]; then
					echo
					echo -e " Maaf ... jika Anda ingin menggunakan${cyan} ${transport[$v2ray_transport_opt - 1]} $none Protokol Transfer.. ${red}Shadowsocks Port tidak boleh 80 atau 443 ...$none"
					echo
					echo -e " Port Shadowsocks saat ini: ${cyan}$ssport$none"
					error
				else
					echo
					echo
					echo -e "$yellow Protokol transmisi V2Ray = $cyan${transport[$v2ray_transport_opt - 1]}$none"
					echo "----------------------------------------------------------------"
					echo
					break
				fi
				;;
			[1-9] | 1[0-7])
				echo
				echo
				echo -e "$yellow Protokol transmisi V2Ray = $cyan${transport[$v2ray_transport_opt - 1]}$none"
				echo "----------------------------------------------------------------"
				echo
				break
				;;
			*)
				error
				;;
			esac
		fi

	done
	pause

	if [[ $v2ray_transport_opt == 4 || $v2ray_transport_opt == 16 ]]; then
		tls_config
	elif [[ $v2ray_transport_opt -ge 9 && $v2ray_transport_opt -le 15 ]]; then
		v2ray_dynamic_port_start
		v2ray_dynamic_port_end
		pause
		old_transport
		open_port "multiport"
		backup_config v2ray_transport v2ray_dynamicPort_start v2ray_dynamicPort_end
		port_range="${v2ray_dynamic_port_start_input}-${v2ray_dynamic_port_end_input}"
		v2ray_transport=$v2ray_transport_opt
		config
		clear
		view_v2ray_config_info
		download_v2ray_config_ask
	elif [[ $v2ray_transport_opt == 17 ]]; then
		socks_user_config
		socks_pass_config
		pause
		old_transport
		backup_config v2ray_transport username userpass
		v2ray_transport=$v2ray_transport_opt
		username=$new_username
		userpass=$new_userpass
		config
		clear
		view_v2ray_config_info
		download_v2ray_config_ask
	else
		old_transport
		backup_config v2ray_transport
		v2ray_transport=$v2ray_transport_opt
		config
		clear
		view_v2ray_config_info
		download_v2ray_config_ask
	fi

}
old_transport() {
	if [[ $v2ray_transport == 4 || $v2ray_transport == 16 ]]; then
		del_port "80"
		del_port "443"
		if [[ $caddy_installed && $caddy_pid ]]; then
			do_service stop caddy
			if [[ $systemd ]]; then
				systemctl disable caddy >/dev/null 2>&1
			else
				update-rc.d -f caddy remove >/dev/null 2>&1
			fi
		elif [[ $caddy_installed ]]; then
			if [[ $systemd ]]; then
				systemctl disable caddy >/dev/null 2>&1
			else
				update-rc.d -f caddy remove >/dev/null 2>&1
			fi
		fi
		if [[ $is_path ]]; then
			backup_config -path
		fi
	elif [[ $v2ray_transport -ge 9 && $v2ray_transport -le 15 ]]; then
		del_port "multiport"
	fi
}

socks_user_config() {
	echo
	while :; do
		read -p "$(echo -e "silahkan masuk $yellow nama pengguna $none...(Nama pengguna default: ${cyan}233blog$none)"): " new_username
		[ -z "$new_username" ] && new_username="233blog"
		case $new_username in
		*[/$]* | *\&*)
			echo
			echo -e " Karena skrip ini terlalu pedas ... nama pengguna tidak boleh berisi $red / $none atau $red $ $none atau $red & $none Ketiga simbol ini.... "
			echo
			error
			;;
		*)
			echo
			echo
			echo -e "$yellow nama pengguna = $cyan$new_username$none"
			echo "----------------------------------------------------------------"
			echo
			break
			;;
		esac
	done

}
socks_pass_config() {
	echo
	while :; do
		read -p "$(echo -e "silahkan masuk $yellow kata sandi $none...(kata sandi default: ${cyan}233blog.com$none)"): " new_userpass
		[ -z "$new_userpass" ] && new_userpass="233blog.com"
		case $new_userpass in
		*[/$]* | *\&*)
			echo
			echo -e " Karena script ini terlalu pedas ... jadi kata sandinya tidak bisa dimasukkan $red / $none atau $red $ $none atau $red & $none Ketiga simbol ini.... "
			echo
			error
			;;
		*)
			echo
			echo
			echo -e "$yellow kata sandi = $cyan$new_userpass$none"
			echo "----------------------------------------------------------------"
			echo
			break
			;;
		esac
	done
}

tls_config() {
	while :; do
		echo
		echo
		echo
		echo -e "Harap masukkan satu $magenta Nama domain yang benar $none，Itu pasti benar, tidak! bisa! Di luar! salah!"
		read -p "(Misalnya：233blog.com): " new_domain
		[ -z "$new_domain" ] && error && continue
		echo
		echo
		echo -e "$yellow Nama domain Anda = $cyan$new_domain$none"
		echo "----------------------------------------------------------------"
		break
	done
	get_ip
	echo
	echo
	echo -e "$yellow Silahkan $magenta$new_domain$none $yellow Putuskan untuk: $cyan$ip$none"
	echo
	echo -e "$yellow Silahkan $magenta$new_domain$none $yellow Putuskan untuk: $cyan$ip$none"
	echo
	echo -e "$yellow Silahkan $magenta$new_domain$none $yellow Putuskan untuk: $cyan$ip$none"
	echo "----------------------------------------------------------------"
	echo

	while :; do

		read -p "$(echo -e "(Apakah sudah diurai dengan benar: [${magenta}Y$none]):") " record
		if [[ -z "$record" ]]; then
			error
		else
			if [[ "$record" == [Yy] ]]; then
				echo
				echo
				echo -e "$yellow DNS = ${cyan} Saya yakin ada analisisnya $none"
				echo "----------------------------------------------------------------"
				echo
				break
			else
				error
			fi
		fi

	done

	if [[ $caddy_installed ]]; then
		path_config_ask
		pause
		domain_check
		backup_config v2ray_transport domain
		if [[ $new_path ]]; then
			backup_config +path
			path=$new_path
			proxy_site=$new_proxy_site
			is_path=true
		fi

		if [[ $v2ray_transport -ge 9 && $v2ray_transport -le 15 ]]; then
			del_port "multiport"
		fi
		domain=$new_domain

		open_port "80"
		open_port "443"
		if [[ $systemd ]]; then
			systemctl enable caddy >/dev/null 2>&1
		else
			update-rc.d -f caddy defaults >/dev/null 2>&1
		fi
		v2ray_transport=$v2ray_transport_opt
		caddy_config
		config
		clear
		view_v2ray_config_info
		download_v2ray_config_ask
	else
		if [[ $v2ray_transport_opt == 16 ]]; then
			path_config_ask
			pause
			domain_check
			backup_config v2ray_transport domain caddy
			if [[ $new_path ]]; then
				backup_config +path
				path=$new_path
				proxy_site=$new_proxy_site
				is_path=true
			fi
			if [[ $v2ray_transport -ge 9 && $v2ray_transport -le 15 ]]; then
				del_port "multiport"
			fi
			domain=$new_domain
			install_caddy
			open_port "80"
			open_port "443"
			v2ray_transport=$v2ray_transport_opt
			caddy_config
			config
			caddy_installed=true
			clear
			view_v2ray_config_info
			download_v2ray_config_ask
		else
			auto_tls_config
		fi
	fi

}
auto_tls_config() {
	echo -e "

		Instal Caddy untuk mengkonfigurasi TLS secara otomatis
		
		Jika Anda telah menginstal Nginx atau Caddy

		$yellow Dan ... Anda dapat mengkonfigurasi TLS sendiri$none

		Maka tidak perlu mengaktifkan TLS konfigurasi otomatis
		"
	echo "----------------------------------------------------------------"
	echo

	while :; do

		read -p "$(echo -e "(Apakah akan mengonfigurasi TLS secara otomatis: [${magenta}Y/N$none]):") " auto_install_caddy
		if [[ -z "$auto_install_caddy" ]]; then
			error
		else
			if [[ "$auto_install_caddy" == [Yy] ]]; then
				echo
				echo
				echo -e "$yellow Konfigurasi TLS secara otomatis = $cyan nyalakan $none"
				echo "----------------------------------------------------------------"
				echo
				path_config_ask
				pause
				domain_check
				backup_config v2ray_transport domain caddy
				if [[ $new_path ]]; then
					backup_config +path
					path=$new_path
					proxy_site=$new_proxy_site
					is_path=true
				fi
				if [[ $v2ray_transport -ge 9 && $v2ray_transport -le 15 ]]; then
					del_port "multiport"
				fi
				domain=$new_domain
				install_caddy
				open_port "80"
				open_port "443"
				v2ray_transport=$v2ray_transport_opt
				caddy_config
				config
				caddy_installed=true
				clear
				view_v2ray_config_info
				download_v2ray_config_ask
				break
			elif [[ "$auto_install_caddy" == [Nn] ]]; then
				echo
				echo
				echo -e "$yellow Konfigurasi TLS secara otomatis = $cyan mematikan $none"
				echo "----------------------------------------------------------------"
				echo
				pause
				domain_check
				backup_config v2ray_transport domain
				if [[ $v2ray_transport -ge 9 && $v2ray_transport -le 15 ]]; then
					del_port "multiport"
				fi
				domain=$new_domain
				open_port "80"
				open_port "443"
				v2ray_transport=$v2ray_transport_opt
				config
				clear
				view_v2ray_config_info
				download_v2ray_config_ask
				break
			else
				error
			fi
		fi

	done
}

path_config_ask() {
	echo
	while :; do
		echo -e "Apakah akan mengaktifkan kamuflase situs web dan pengalihan jalur [${magenta}Y/N$none]"
		read -p "$(echo -e "(default: [${cyan}N$none]):")" path_ask
		[[ -z $path_ask ]] && path_ask="n"

		case $path_ask in
		Y | y)
			path_config
			break
			;;
		N | n)
			echo
			echo
			echo -e "$yellow Kamuflase situs web dan pengalihan jalur = $cyan Tidak ingin mengkonfigurasi $none"
			echo "----------------------------------------------------------------"
			echo
			break
			;;
		*)
			error
			;;
		esac
	done
}
path_config() {
	echo
	while :; do
		echo -e "Silakan masukkan apa yang Anda inginkan ${magenta}Jalur yang digunakan untuk mengalihkan $none , Misalnya /233blog , Lalu masuk saja 233blog Bisa"
		read -p "$(echo -e "(default: [${cyan}233blog$none]):")" new_path
		[[ -z $new_path ]] && new_path="233blog"

		case $new_path in
		*[/$]*)
			echo
			echo -e " Karena skrip ini terlalu pedas ... jadi jalur pengalihan tidak dapat disertakan $red / $none atau $red $ $none Dua simbol ini.... "
			echo
			error
			;;
		*)
			echo
			echo
			echo -e "$yellow Jalur yang menyimpang = ${cyan}/${new_path}$none"
			echo "----------------------------------------------------------------"
			echo
			break
			;;
		esac
	done
	proxy_site_config
}
proxy_site_config() {
	echo
	while :; do
		echo -e "silahkan masuk ${magenta}Benar$none ${cyan}URL$none Digunakan sebagai ${cyan}Kamuflase$none , Misalnya https://liyafly.com"
		echo -e "Contoh ... Dengan asumsi nama domain Anda saat ini adalah $green $domain $none, URL palsu adalah https://liyafly.com"
		echo -e "Kemudian ketika Anda membuka nama domain Anda ... konten yang ditampilkan adalah dari https://liyafly.com Kandungan"
		echo -e "Ini sebenarnya adalah generasi kontra ......"
		echo -e "Jika penyamaran tidak berhasil ... Anda dapat menggunakan konfigurasi v2ray untuk mengubah URL yang disamarkan"
		read -p "$(echo -e "(default: [${cyan}https://liyafly.com$none]):")" new_proxy_site
		[[ -z $new_proxy_site ]] && new_proxy_site="https://liyafly.com"

		case $new_proxy_site in
		*[#$]*)
			echo
			echo -e " Karena skrip ini terlalu pedas ... jadi URL yang disamarkan tidak boleh berisi$red # $none atau $red $ $none Dua simbol ini.... "
			echo
			error
			;;
		*)
			echo
			echo
			echo -e "$yellow URL terselubung = ${cyan}${new_proxy_site}$none"
			echo "----------------------------------------------------------------"
			echo
			break
			;;
		esac
	done
}

install_caddy() {
	if [[ $cmd == "yum" ]]; then
		[[ $(pgrep "httpd") ]] && systemctl stop httpd
		[[ $(command -v httpd) ]] && yum remove httpd -y
	else
		[[ $(pgrep "apache2") ]] && service apache2 stop
		[[ $(command -v apache2) ]] && apt-get remove apache2* -y
	fi
	local caddy_tmp="/tmp/install_caddy/"
	local caddy_tmp_file="/tmp/install_caddy/caddy.tar.gz"
	if [[ $sys_bit == "i386" || $sys_bit == "i686" ]]; then
		local caddy_download_link="https://caddyserver.com/download/linux/386?license=personal"
	elif [[ $sys_bit == "x86_64" ]]; then
		local caddy_download_link="https://caddyserver.com/download/linux/amd64?license=personal"
	else
		echo -e "$red Penginstalan otomatis Caddy gagal! Tidak mendukung sistem Anda。$none" && exit 1
	fi

	mkdir -p $caddy_tmp

	if ! wget --no-check-certificate -O "$caddy_tmp_file" $caddy_download_link; then
		echo -e "$red Download Caddy gagal！$none" && exit 1
	fi

	tar zxf $caddy_tmp_file -C $caddy_tmp
	cp -f ${caddy_tmp}caddy /usr/local/bin/

	if [[ ! -f /usr/local/bin/caddy ]]; then
		echo -e "$red Terjadi kesalahan saat menginstal Caddy！" && exit 1
	fi

	setcap CAP_NET_BIND_SERVICE=+eip /usr/local/bin/caddy

	if [[ $systemd ]]; then
		cp -f ${caddy_tmp}init/linux-systemd/caddy.service /lib/systemd/system/
		# sed -i "s/www-data/root/g" /lib/systemd/system/caddy.service
		systemctl enable caddy
	else
		cp -f ${caddy_tmp}init/linux-sysvinit/caddy /etc/init.d/caddy
		# sed -i "s/www-data/root/g" /etc/init.d/caddy
		chmod +x /etc/init.d/caddy
		update-rc.d -f caddy defaults
	fi

	mkdir -p /etc/ssl/caddy

	if [ -z "$(grep www-data /etc/passwd)" ]; then
		useradd -M -s /usr/sbin/nologin www-data
	fi
	chown -R www-data.www-data /etc/ssl/caddy

	mkdir -p /etc/caddy/
	rm -rf $caddy_tmp

}
caddy_config() {
	local email=$(shuf -i1-10000000000 -n1)
	case $v2ray_transport in
	4)
		if [[ $is_path ]]; then
			cat >/etc/caddy/Caddyfile <<-EOF
$domain {
    tls ${email}@gmail.com
    gzip
	timeouts none
    proxy / $proxy_site {
        without /${path}
    }
    proxy /${path} 127.0.0.1:${v2ray_port} {
        without /${path}
        websocket
    }
}
		EOF
		else
			cat >/etc/caddy/Caddyfile <<-EOF
$domain {
    tls ${email}@gmail.com
	timeouts none
	proxy / 127.0.0.1:${v2ray_port} {
		websocket
	}
}
		EOF
		fi
		;;
	16)
		if [[ $is_path ]]; then
			cat >/etc/caddy/Caddyfile <<-EOF
$domain {
    tls ${email}@gmail.com
    gzip
	timeouts none
    proxy / $proxy_site {
        without /${path}
    }
    proxy /${path} https://127.0.0.1:${v2ray_port} {
        header_upstream Host {host}
		header_upstream X-Forwarded-Proto {scheme}
		insecure_skip_verify
    }
}
		EOF
		else
			cat >/etc/caddy/Caddyfile <<-EOF
$domain {
    tls ${email}@gmail.com
	timeouts none
	proxy / https://127.0.0.1:${v2ray_port} {
        header_upstream Host {host}
		header_upstream X-Forwarded-Proto {scheme}
		insecure_skip_verify
	}
}
		EOF
		fi
		;;

	esac
	# systemctl restart caddy
	do_service restart caddy
}
v2ray_dynamic_port_start() {
	echo
	echo
	while :; do
		echo -e "silahkan masuk "$yellow"Port dinamis V2Ray mulai "$none"jarak ["$magenta"1-65535"$none"]"
		read -p "$(echo -e "(Port awal default: ${cyan}10000$none):")" v2ray_dynamic_port_start_input
		[ -z $v2ray_dynamic_port_start_input ] && v2ray_dynamic_port_start_input=10000
		case $v2ray_dynamic_port_start_input in
		$v2ray_port)
			echo
			echo " Tidak sama dengan port V2Ray...."
			error
			;;
		[1-9] | [1-9][0-9] | [1-9][0-9][0-9] | [1-9][0-9][0-9][0-9] | [1-5][0-9][0-9][0-9][0-9] | 6[0-4][0-9][0-9][0-9] | 65[0-4][0-9][0-9] | 655[0-3][0-5])
			if [[ $shadowsocks ]] && [[ $v2ray_dynamic_port_start_input == $ssport ]]; then
				echo
				echo " Tidak sama dengan pelabuhan Shadowsocks...."
				error
			else
				echo
				echo
				echo -e "$yellow Port dinamis V2Ray mulai = $cyan$v2ray_dynamic_port_start_input$none"
				echo "----------------------------------------------------------------"
				echo
				break
			fi

			;;
		*)
			error
			;;
		esac

	done

	if [[ $v2ray_dynamic_port_start_input -lt $v2ray_port ]]; then
		lt_v2ray_port=true
	fi
	if [[ $shadowsocks ]] && [[ $v2ray_dynamic_port_start_input -lt $ssport ]]; then
		lt_ssport=true
	fi

}

v2ray_dynamic_port_end() {
	echo
	while :; do
		echo -e "silahkan masuk "$yellow"Ujung port dinamis V2Ray "$none"jarak ["$magenta"1-65535"$none"]"
		read -p "$(echo -e "(Port akhir default: ${cyan}20000$none):")" v2ray_dynamic_port_end_input
		[ -z $v2ray_dynamic_port_end_input ] && v2ray_dynamic_port_end_input=20000
		case $v2ray_dynamic_port_end_input in
		[1-9] | [1-9][0-9] | [1-9][0-9][0-9] | [1-9][0-9][0-9][0-9] | [1-5][0-9][0-9][0-9][0-9] | 6[0-4][0-9][0-9][0-9] | 65[0-4][0-9][0-9] | 655[0-3][0-5])

			if [[ $v2ray_dynamic_port_end_input -le $v2ray_dynamic_port_start_input ]]; then
				echo
				echo " Tidak boleh kurang dari atau sama dengan rentang awal port dinamis V2Ray"
				error
			elif [ $lt_v2ray_port ] && [[ ${v2ray_dynamic_port_end_input} -ge $v2ray_port ]]; then
				echo
				echo " VRentang akhir port dinamis 2Ray tidak dapat menyertakan port V2Ray..."
				echo
				echo -e " Port V2Ray saat ini: ${cyan}$v2ray_port$none"
				error
			elif [ $lt_ssport ] && [[ ${v2ray_dynamic_port_end_input} -ge $ssport ]]; then
				echo
				echo " Rentang akhir port dinamis V2Ray tidak dapat menyertakan port Shadowsocks..."
				echo
				echo -e " Port Shadowsocks saat ini: ${cyan}$ssport$none"
				error
			else
				echo
				echo
				echo -e "$yellow Ujung port dinamis V2Ray = $cyan$v2ray_dynamic_port_end_input$none"
				echo "----------------------------------------------------------------"
				echo
				break
			fi
			;;
		*)
			error
			;;
		esac

	done

}
change_v2ray_dynamicport() {
	if [[ $v2ray_transport -ge 9 && $v2ray_transport -le 15 ]]; then
		change_v2ray_dynamic_port_start
		change_v2ray_dynamic_port_end
		pause
		del_port "multiport"
		open_port "multiport"
		backup_config v2ray_dynamicPort_start v2ray_dynamicPort_end
		port_range="${v2ray_dynamic_port_start_input}-${v2ray_dynamic_port_end_input}"
		config
		# clear
		echo
		echo -e "$green Porta dinamis telah berhasil dimodifikasi ... Anda tidak perlu mengubah konfigurasi klien V2Ray ... cukup pertahankan konfigurasi asli...$none"
		echo
	else
		echo
		echo -e "$red ...Protokol transmisi saat ini tidak mengaktifkan port dinamis...$none"
		echo
		while :; do
			echo -e "Perlu mengubah protokol transmisi [${magenta}Y/N$none]"
			read -p "$(echo -e "default [${cyan}N$none]:")" y_n
			if [[ -z $y_n ]]; then
				echo
				echo -e "$green Modifikasi protokol transfer telah dibatalkan...$none"
				echo
				break
			else
				if [[ $y_n == [Yy] ]]; then
					change_v2ray_transport
					break
				elif [[ $y_n == [Nn] ]]; then
					echo
					echo -e "$green Modifikasi protokol transfer telah dibatalkan...$none"
					echo
					break
				else
					error
				fi
			fi
		done

	fi
}
change_v2ray_dynamic_port_start() {
	echo
	echo
	while :; do
		echo -e "silahkan masuk "$yellow"Port dinamis V2Ray mulai "$none"jarak ["$magenta"1-65535"$none"]"
		read -p "$(echo -e "(Port awal dinamis saat ini: ${cyan}$v2ray_dynamicPort_start$none):")" v2ray_dynamic_port_start_input
		[ -z $v2ray_dynamic_port_start_input ] && error && continue
		case $v2ray_dynamic_port_start_input in
		$v2ray_port)
			echo
			echo " Tidak sama dengan port V2Ray...."
			error
			;;
		[1-9] | [1-9][0-9] | [1-9][0-9][0-9] | [1-9][0-9][0-9][0-9] | [1-5][0-9][0-9][0-9][0-9] | 6[0-4][0-9][0-9][0-9] | 65[0-4][0-9][0-9] | 655[0-3][0-5])
			if [[ $shadowsocks ]] && [[ $v2ray_dynamic_port_start_input == $ssport ]]; then
				echo
				echo " Tidak sama dengan pelabuhan Shadowsocks...."
				error
			else
				echo
				echo
				echo -e "$yellow Port dinamis V2Ray mulai = $cyan$v2ray_dynamic_port_start_input$none"
				echo "----------------------------------------------------------------"
				echo
				break
			fi

			;;
		*)
			error
			;;
		esac

	done

	if [[ $v2ray_dynamic_port_start_input -lt $v2ray_port ]]; then
		lt_v2ray_port=true
	fi
	if [[ $shadowsocks ]] && [[ $v2ray_dynamic_port_start_input -lt $ssport ]]; then
		lt_ssport=true
	fi

}

change_v2ray_dynamic_port_end() {
	echo
	while :; do
		echo -e "silahkan masuk "$yellow"Ujung port dinamis V2Ray "$none"jarak ["$magenta"1-65535"$none"]"
		read -p "$(echo -e "(Port akhir dinamis saat ini: ${cyan}$v2ray_dynamicPort_end$none):")" v2ray_dynamic_port_end_input
		[ -z $v2ray_dynamic_port_end_input ] && error && continue
		case $v2ray_dynamic_port_end_input in
		[1-9] | [1-9][0-9] | [1-9][0-9][0-9] | [1-9][0-9][0-9][0-9] | [1-5][0-9][0-9][0-9][0-9] | 6[0-4][0-9][0-9][0-9] | 65[0-4][0-9][0-9] | 655[0-3][0-5])

			if [[ $v2ray_dynamic_port_end_input -le $v2ray_dynamic_port_start_input ]]; then
				echo
				echo " Tidak boleh kurang dari atau sama dengan rentang awal port dinamis V2Ray"
				error
			elif [ $lt_v2ray_port ] && [[ ${v2ray_dynamic_port_end_input} -ge $v2ray_port ]]; then
				echo
				echo " Rentang akhir port dinamis V2Ray tidak dapat menyertakan port V2Ray..."
				echo
				echo -e " Port V2Ray saat ini: ${cyan}$v2ray_port$none"
				error
			elif [ $lt_ssport ] && [[ ${v2ray_dynamic_port_end_input} -ge $ssport ]]; then
				echo
				echo " Rentang akhir port dinamis V2Ray tidak dapat menyertakan port Shadowsocks..."
				echo
				echo -e " Port Shadowsocks saat ini: ${cyan}$ssport$none"
				error
			else
				echo
				echo
				echo -e "$yellow Ujung port dinamis V2Ray = $cyan$v2ray_dynamic_port_end_input$none"
				echo "----------------------------------------------------------------"
				echo
				break
			fi
			;;
		*)
			error
			;;
		esac

	done

}
change_v2ray_id() {
	echo
	while :; do
		echo -e "Apakah Anda yakin ingin mengubah ID pengguna [${magenta}Y/N$none]"
		read -p "$(echo -e "default [${cyan}N$none]:")" y_n
		if [[ -z $y_n ]]; then
			echo
			echo -e "$green Modifikasi ID pengguna dibatalkan...$none"
			echo
			break
		else
			if [[ $y_n == [Yy] ]]; then
				echo
				echo
				echo -e "$yellow Ubah ID pengguna = $cyan menentukan $none"
				echo "----------------------------------------------------------------"
				echo
				pause
				# sed -i "21s/$v2ray_id/$uuid/;" $backup
				backup_config uuid
				v2ray_id=$uuid
				config
				clear
				view_v2ray_config_info
				download_v2ray_config_ask
				break
			elif [[ $y_n == [Nn] ]]; then
				echo
				echo -e "$green Modifikasi ID pengguna dibatalkan...$none"
				echo
				break
			else
				error
			fi
		fi
	done
}
change_domain() {
	if [[ $v2ray_transport == 4 || $v2ray_transport == 16 ]] && [[ $caddy_installed ]]; then
		while :; do
			echo
			echo -e "Harap masukkan satu $magenta Nama domain yang benar $none，Itu pasti benar, tidak! bisa! Di luar! salah!"
			read -p "$(echo -e "(Nama domain saat ini: ${cyan}$domain$none):") " new_domain
			[ -z "$new_domain" ] && error && continue
			if [[ $new_domain == $domain ]]; then
				echo
				echo -e " Ini sama dengan nama domain saat ini ... Ubahlah"
				echo
				error && continue
			fi
			echo
			echo
			echo -e "$yellow Nama domain Anda = $cyan$new_domain$none"
			echo "----------------------------------------------------------------"
			break
		done
		get_ip
		echo
		echo
		echo -e "$yellow Silahkan $magenta$new_domain$none $yellow Putuskan untuk: $cyan$ip$none"
		echo
		echo -e "$yellow Silahkan $magenta$new_domain$none $yellow Putuskan untuk: $cyan$ip$none"
		echo
		echo -e "$yellow Silahkan $magenta$new_domain$none $yellow Putuskan untuk: $cyan$ip$none"
		echo "----------------------------------------------------------------"
		echo

		while :; do

			read -p "$(echo -e "(Apakah sudah diurai dengan benar: [${magenta}Y$none]):") " record
			if [[ -z "$record" ]]; then
				error
			else
				if [[ "$record" == [Yy] ]]; then
					echo
					echo
					echo -e "$yellow DNS = ${cyan} Saya yakin ada analisisnya $none"
					echo "----------------------------------------------------------------"
					echo
					pause
					domain_check
					# sed -i "27s/$domain/$new_domain/" $backup
					backup_config domain
					domain=$new_domain
					caddy_config
					config
					clear
					view_v2ray_config_info
					download_v2ray_config_ask
					break
				else
					error
				fi
			fi

		done
	else
		echo
		echo -e "$red Maaf ... pengeditan tidak didukung...$none"
		echo
		echo -e " Catatan: Ubah nama domain TLS hanya mendukung protokol transfer sebagai ${yellow}WebSocket + TLS$none atau ${yellow}HTTP/2$none dan $yellow Konfigurasi otomatis TLS = on $none"
		echo
		echo -e " Protokol transmisi saat ini adalah: ${cyan}${transport[$v2ray_transport - 1]}${none}"
		echo
		if [[ $caddy_installed ]]; then
			echo -e " Konfigurasi TLS secara otomatis = ${cyan} nyalakan $none"
		else
			echo -e " Konfigurasi TLS secara otomatis = $red mematikan $none"
		fi
		echo
	fi
}
change_path_config() {
	if [[ $v2ray_transport == 4 || $v2ray_transport == 16 ]] && [[ $caddy_installed && $is_path ]]; then
		echo
		while :; do
			echo -e "Silakan masukkan apa yang Anda inginkan ${magenta} Jalur yang digunakan untuk mengalihkan $none , Misalnya /233blog , Lalu masuk saja 233blog Bisa"
			read -p "$(echo -e "(Jalur pengalihan saat ini: [${cyan}/${path}$none]):")" new_path
			[[ -z $new_path ]] && error && continue

			case $new_path in
			$path)
				echo
				echo -e " Bos ... itu sama dengan jalur pengalihan saat ini ... Ubahlah "
				echo
				error
				;;
			*[/$]*)
				echo
				echo -e " Karena skrip ini terlalu pedas ... jadi jalur pengalihan tidak dapat disertakan $red / $none atau $red $ $none Dua simbol ini.... "
				echo
				error
				;;
			*)
				echo
				echo
				echo -e "$yellow Jalur yang menyimpang = ${cyan}/${new_path}$none"
				echo "----------------------------------------------------------------"
				echo
				break
				;;
			esac
		done
		pause
		backup_config path
		path=$new_path
		caddy_config
		config
		clear
		view_v2ray_config_info
		download_v2ray_config_ask
	elif [[ $v2ray_transport == 4 || $v2ray_transport == 16 ]] && [[ $caddy_installed ]]; then
		path_config_ask
		if [[ $new_path ]]; then
			backup_config +path
			path=$new_path
			proxy_site=$new_proxy_site
			is_path=true
			caddy_config
			config
			clear
			view_v2ray_config_info
			download_v2ray_config_ask
		else
			echo
			echo
			echo " Berikan jempol pada pria besar itu .... Jadi, dengan tegas menyerah konfigurasi penyamaran situs web dan pengalihan jalur"
			echo
			echo
		fi
	else
		echo
		echo -e "$red Maaf ... pengeditan tidak didukung...$none"
		echo
		echo -e " Catatan: Ubah jalur shunt Satu-satunya protokol transmisi yang didukung adalah ${yellow}WebSocket + TLS$none atau ${yellow}HTTP/2$none dan$yellow Konfigurasi TLS secara otomatis = nyalakan $none"
		echo
		echo -e " Protokol transmisi saat ini adalah: ${cyan}${transport[$v2ray_transport - 1]}${none}"
		echo
		if [[ $caddy_installed ]]; then
			echo -e " Konfigurasi TLS secara otomatis = ${cyan} nyalakan $none"
		else
			echo -e " Konfigurasi TLS secara otomatis = $red mematikan $none"
		fi
		echo
		change_v2ray_transport_ask
	fi

}
change_proxy_site_config() {
	if [[ $v2ray_transport == 4 || $v2ray_transport == 16 ]] && [[ $caddy_installed && $is_path ]]; then
		echo
		while :; do
			echo -e "silahkan masuk ${magenta} Benar $none ${cyan} URL $none Digunakan sebagai ${cyan} Kamuflase $none , Misalnya https://liyafly.com"
			echo -e "Misalnya ... nama domain Anda saat ini adalah $green $domain $none, URL palsu adalah https://liyafly.com"
			echo -e "Kemudian ketika Anda membuka nama domain Anda ... konten yang ditampilkan adalah dari https://liyafly.com Kandungan"
			echo -e "Ini sebenarnya adalah generasi kontra ......"
			echo -e "Jika penyamaran tidak berhasil ... Anda dapat menggunakan konfigurasi v2ray untuk mengubah URL yang disamarkan"
			read -p "$(echo -e "(URL saat ini disamarkan: [${cyan}${proxy_site}$none]):")" new_proxy_site
			[[ -z $new_proxy_site ]] && error && continue

			case $new_proxy_site in
			*[#$]*)
				echo
				echo -e " Karena skrip ini terlalu pedas ... jadi URL yang disamarkan tidak boleh berisi $red # $none atau $red $ $none Dua simbol ini.... "
				echo
				error
				;;
			*)
				echo
				echo
				echo -e "$yellow URL terselubung = ${cyan}${new_proxy_site}$none"
				echo "----------------------------------------------------------------"
				echo
				break
				;;
			esac
		done
		pause
		backup_config proxy_site
		proxy_site=$new_proxy_site
		caddy_config
		echo
		echo
		echo " Aduh ... sepertinya modifikasinya berhasil..."
		echo
		echo -e " Buka nama domain Anda dengan cepat ${cyan}https://${domain}$none Coba lihat"
		echo
		echo
	elif [[ $v2ray_transport == 4 || $v2ray_transport == 16 ]] && [[ $caddy_installed ]]; then
		path_config_ask
		if [[ $new_path ]]; then
			backup_config +path
			path=$new_path
			proxy_site=$new_proxy_site
			is_path=true
			caddy_config
			config
			clear
			view_v2ray_config_info
			download_v2ray_config_ask
		else
			echo
			echo
			echo " Berikan jempol pada pria besar itu .... Jadi, dengan tegas menyerah konfigurasi penyamaran situs web dan pengalihan jalur"
			echo
			echo
		fi
	else
		echo
		echo -e "$red Maaf ... pengeditan tidak didukung...$none"
		echo
		echo -e " Catatan: ubah URL yang disamarkan dan hanya mendukung protokol transmisi sebagai ${yellow}WebSocket + TLS$none atau ${yellow}HTTP/2$none dan $yellow Konfigurasi TLS secara otomatis = nyalakan $none"
		echo
		echo -e " Protokol transmisi saat ini adalah: ${cyan}${transport[$v2ray_transport - 1]}${none}"
		echo
		if [[ $caddy_installed ]]; then
			echo -e " Konfigurasi otomatis TLS = ${cyan} nyalakan $none"
		else
			echo -e " Konfigurasi otomatis TLS = $red mematikan $none"
		fi
		echo
		change_v2ray_transport_ask
	fi

}
domain_check() {
	# test_domain=$(dig $new_domain +short)
	test_domain=$(ping $new_domain -c 1 | grep -oE -m1 "([0-9]{1,3}\.){3}[0-9]{1,3}")
	if [[ $test_domain != $ip ]]; then
		echo
		echo -e "$red Mendeteksi kesalahan resolusi nama domain....$none"
		echo
		echo -e " Nama domain Anda: $yellow$new_domain$none Belum terselesaikan: $cyan$ip$none"
		echo
		echo -e " Nama domain Anda saat ini diselesaikan menjadi: $cyan$test_domain$none"
		echo
		echo "Keterangan ... Jika nama domain Anda diselesaikan oleh Cloudflare ... klik ikon di Status ... buat abu-abu"
		echo
		exit 1
	fi
}
disable_path() {
	if [[ $v2ray_transport == 4 || $v2ray_transport == 16 ]] && [[ $caddy_installed && $is_path ]]; then
		echo

		while :; do
			echo -e "Apakah akan ditutup ${yellow}Kamuflase situs web dan pengalihan jalur${none} [${magenta}Y/N$none]"
			read -p "$(echo -e "(default [${cyan}N$none]):") " y_n
			[[ -z "$y_n" ]] && y_n="n"
			if [[ "$y_n" == [Yy] ]]; then
				echo
				echo
				echo -e "$yellow Matikan kamuflase situs dan pengalihan jalur = $cyan是$none"
				echo "----------------------------------------------------------------"
				echo
				pause
				backup_config -path
				is_path=''
				caddy_config
				config
				clear
				view_v2ray_config_info
				download_v2ray_config_ask
				break
			elif [[ "$y_n" == [Nn] ]]; then
				echo
				echo -e " $green Penyamaran situs web dan pengalihan jalur yang tidak ditutup ....$none"
				echo
				break
			else
				error
			fi

		done
	else
		echo
		echo -e "$red Maaf ... pengeditan tidak didukung...$none"
		echo
		echo -e " Protokol transmisi saat ini adalah: ${cyan}${transport[$v2ray_transport - 1]}${none}"
		echo
		if [[ $caddy_installed ]]; then
			echo -e " KKonfigurasi TLS secara otomatis = ${cyan} nyalakan $none"
		else
			echo -e " Konfigurasi TLS secara otomatis = $red mematikan $none"
		fi
		echo
		if [[ $is_path ]]; then
			echo -e " Pengalihan jalan = ${cyan} nyalakan $none"
		else
			echo -e " Pengalihan jalan = $red mematikan $none"
		fi
		echo
		echo -e " Harus berupa protokol transmisi WebSocket + TLS atau HTTP / 2, yang secara otomatis mengkonfigurasi TLS= ${cyan} nyalakan $none, Pengalihan jalan = ${cyan} nyalakan $none, Dapat memodifikasi"
		echo

	fi
}
blocked_hosts() {
	if [[ $is_blocked_ad ]]; then
		local _info="$green Diaktifkan $none"
	else
		local _info="$red Tutup $none"
	fi
	_opt=''
	while :; do
		echo
		echo -e "$yellow 1. $none Aktifkan pemblokiran iklan"
		echo
		echo -e "$yellow 2. $none Matikan pemblokiran iklan"
		echo
		echo "Catatan: Pemblokiran iklan didasarkan pada pemblokiran nama domain ... jadi ini dapat menyebabkan beberapa elemen menjadi kosong saat menjelajahi web ... atau masalah lainnya"
		echo
		echo "Umpan balik atau permintaan untuk memblokir lebih banyak domain: https://github.com/233boy/v2ray/issues"
		echo
		echo -e "Status pemblokiran iklan saat ini: $_info"
		echo
		read -p "$(echo -e "tolong pilih [${magenta}1-2$none]:")" _opt
		if [[ -z $_opt ]]; then
			error
		else
			case $_opt in
			1)
				if [[ $is_blocked_ad ]]; then
					echo
					echo -e " Kakak berpayudara besar...Mungkinkah Anda tidak melihat (Status pemblokiran iklan saat ini: $_info) Apakah pengingat yang bagus ini?..... Buka juga penisnya"
					echo
				else
					echo
					echo
					echo -e "$yellow Pemblokiran iklan = $cyan Nyalakan $none"
					echo "----------------------------------------------------------------"
					echo
					pause
					# sed -i "39s/false/true/" $backup
					backup_config +ad
					is_blocked_ad=true
					config
					echo
					echo
					echo -e "$green Pemblokiran iklan dihidupkan ... Jika ada yang tidak normal ... maka matikan $none"
					echo
				fi
				break
				;;
			2)
				if [[ $is_blocked_ad ]]; then
					echo
					echo
					echo -e "$yellow Pemblokiran iklan = $cyan mematikan $none"
					echo "----------------------------------------------------------------"
					echo
					pause
					# sed -i "39s/true/false/" $backup
					backup_config -ad
					is_blocked_ad=''
					config
					echo
					echo
					echo -e "$red Pemblokiran iklan dinonaktifkan ... tetapi Anda dapat mengaktifkannya kembali kapan saja ... selama Anda mau $none"
					echo
				else
					echo
					echo -e " Kakak berpayudara besar ... Apakah mungkin Anda tidak melihat (status pemblokiran iklan saat ini: $_info) Apakah pengingat yang tampan ini ... juga menutup penis?"
					echo
				fi
				break
				;;
			*)
				error
				;;
			esac
		fi
	done

}
change_v2ray_alterId() {
	echo
	while :; do
		echo -e "silahkan masuk ${yellow}alterId${none} Nilai dari [${magenta}0-65535$none]"
		read -p "$(echo -e "(Nilai saat ini adalah: ${cyan}$alterId$none):") " new_alterId
		[[ -z $new_alterId ]] && error && continue
		case $new_alterId in
		$alterId)
			echo
			echo -e " Orang besar ... itu sama dengan alterId saat ini ... memodifikasinya "
			echo
			error
			;;
		[0-9] | [1-9][0-9] | [1-9][0-9][0-9] | [1-9][0-9][0-9][0-9] | [1-5][0-9][0-9][0-9][0-9] | 6[0-4][0-9][0-9][0-9] | 65[0-4][0-9][0-9] | 655[0-3][0-5])
			echo
			echo
			echo -e "$yellow alterId = $cyan$new_alterId$none"
			echo "----------------------------------------------------------------"
			echo
			pause
			backup_config alterId
			alterId=$new_alterId
			config
			clear
			view_v2ray_config_info
			download_v2ray_config_ask
			break
			;;
		*)
			error
			;;
		esac
	done
}
change_socks_user_config() {
	if [[ $v2ray_transport == 17 ]]; then
		echo
		while :; do
			read -p "$(echo -e "silahkan masuk $yellow nama pengguna $none...(Nama pengguna saat ini: ${cyan}$username$none)"): " new_username
			[ -z "$new_username" ] && error && continue
			case $new_username in
			$username)
				echo
				echo -e " Orang besar ... itu sama dengan nama pengguna saat ini ... ubahlah "
				echo
				error
				;;
			*[/$]* | *\&*)
				echo
				echo -e " Karena skrip ini terlalu pedas ... nama pengguna tidak boleh berisi $red / $none atau $red $ $none atau $red & $none Ketiga simbol ini.... "
				echo
				error
				;;
			*)
				echo
				echo
				echo -e "$yellow nama pengguna = $cyan$new_username$none"
				echo "----------------------------------------------------------------"
				echo
				pause
				backup_config username
				username=$new_username
				config
				clear
				view_v2ray_config_info
				download_v2ray_config_ask
				break
				;;
			esac
		done
	else
		echo
		echo -e "$red Ups ... tidak mendukung modifikasi...$none"
		echo
		echo -e " harus menggunakan..${cyan} Socks5 $none Protokol transmisi dapat dimodifikasi"
		echo
		echo -e " Protokol transmisi saat ini adalah: ${cyan}${transport[$v2ray_transport - 1]}${none}"
		echo
	fi
}
change_socks_pass_config() {
	if [[ $v2ray_transport == 17 ]]; then
		echo
		while :; do
			read -p "$(echo -e "silahkan masuk $yellow kata sandi $none...(kata sandi saat ini: ${cyan}$userpass$none)"): " new_userpass
			[ -z "$new_userpass" ] && error && continue
			case $new_userpass in
			$userpass)
				echo
				echo -e " Bos ... itu sama dengan kata sandi saat ini ... ubahlah "
				echo
				error
				;;
			*[/$]* | *\&*)
				echo
				echo -e " Karena script ini terlalu pedas ... jadi kata sandinya tidak bisa dimasukkan $red / $none或$red $ $none atau $red & $none Ketiga simbol ini.... "
				echo
				error
				;;
			*)
				echo
				echo
				echo -e "$yellow kata sandi = $cyan$new_userpass$none"
				echo "----------------------------------------------------------------"
				echo
				pause
				backup_config userpass
				userpass=$new_userpass
				config
				clear
				view_v2ray_config_info
				download_v2ray_config_ask
				break
				;;
			esac
		done
	else
		echo
		echo -e "$red Ups ... tidak mendukung modifikasi...$none"
		echo
		echo -e " harus menggunakan..${cyan} Socks5 $none Protokol transmisi dapat dimodifikasi"
		echo
		echo -e " Protokol transmisi saat ini adalah: ${cyan}${transport[$v2ray_transport - 1]}${none}"
		echo
	fi
}
socks_check() {
	if [[ $v2ray_transport == 17 ]]; then
		echo
		echo -e " Ups ... Karena Anda saat ini menggunakan protokol transmisi Socks5 ... tidak mungkin untuk melakukan fungsi ini..."
		echo
		echo -e " Jika Anda ingin melihat informasi konfigurasi Socks5 ... silakan gunakan $cyan v2ray info $none"
		echo
		exit 1
	fi
}
custom_uuid() {
	echo
	while :; do
		echo -e "silahkan masuk $yello disesuaikan UUID $none...(${cyan}UUID Formatnya harus benar!!!$none)"
		read -p "$(echo -e "(当前 UUID: ${cyan}${v2ray_id}$none)"): " myuuid
		[ -z "$myuuid" ] && error && continue
		case $myuuid in
		$v2ray_id)
			echo
			echo -e " Orang besar ... sama dengan UUID saat ini ... memodifikasinya "
			echo
			error
			;;
		*[/$]* | *\&*)
			echo
			echo -e " Karena skrip ini terlalu pedas ... jadi UUID tidak dapat memuat $red / $none atau $red $ $none atau $red & $none Ketiga simbol ini.... "
			echo
			error
			;;
		*)
			echo
			echo
			echo -e "$yellow UUID = $cyan$myuuid$none"
			echo
			echo -e " Jika format UUID salah.. V2Ray akan berlutut...menggunakan $cyan v2ray reuuid $none kebangkitan"
			echo "----------------------------------------------------------------"
			echo
			pause
			uuid=$myuuid
			backup_config uuid
			v2ray_id=$uuid
			config
			clear
			view_v2ray_config_info
			download_v2ray_config_ask
			break
			;;
		esac
	done
}
v2ray_service() {
	while :; do
		echo
		echo -e "$yellow 1. $none Mulai V2Ray"
		echo
		echo -e "$yellow 2. $none Hentikan V2Ray"
		echo
		echo -e "$yellow 3. $none Mulai ulang V2Ray"
		echo
		echo -e "$yellow 4. $none Lihat log akses"
		echo
		echo -e "$yellow 5. $none Lihat log kesalahan"
		echo
		read -p "$(echo -e "tolong pilih [${magenta}1-5$none]:")" _opt
		if [[ -z $_opt ]]; then
			error
		else
			case $_opt in
			1)
				start_v2ray
				break
				;;
			2)
				stop_v2ray
				break
				;;
			3)
				restart_v2ray
				break
				;;
			4)
				view_v2ray_log
				break
				;;
			5)
				view_v2ray_error_log
				break
				;;
			*)
				error
				;;
			esac
		fi
	done
}
start_v2ray() {
	if [[ $v2ray_pid ]]; then
		echo
		echo -e "${green} V2Ray sedang berjalan ... tidak perlu memulai $none"
		echo
	else

		# systemctl start v2ray
		service v2ray start >/dev/null 2>&1
		local is_v2ray_pid=$(ps ux | grep "/usr/bin/v2ray/v2ray" | grep -v grep | awk '{print $2}')
		if [[ $is_v2ray_pid ]]; then
			echo
			echo -e "${green} V2Ray telah dimulai $none"
			echo
		else
			echo
			echo -e "${red} V2Ray gagal dimulai！$none"
			echo
		fi

	fi
}
stop_v2ray() {
	if [[ $v2ray_pid ]]; then
		# systemctl stop v2ray
		service v2ray stop >/dev/null 2>&1
		echo
		echo -e "${green} V2Ray berhenti $none"
		echo
	else
		echo
		echo -e "${red} V2Ray tidak berjalan $none"
		echo
	fi
}
restart_v2ray() {
	# systemctl restart v2ray
	service v2ray restart >/dev/null 2>&1
	local is_v2ray_pid=$(ps ux | grep "/usr/bin/v2ray/v2ray" | grep -v grep | awk '{print $2}')
	if [[ $is_v2ray_pid ]]; then
		echo
		echo -e "${green} V2Ray restart selesai $none"
		echo
	else
		echo
		echo -e "${red} Restart V2Ray gagal！$none"
		echo
	fi
}
view_v2ray_log() {
	echo
	echo -e "$green Tekan Ctrl + C untuk keluar...$none"
	echo
	tail -f /var/log/v2ray/access.log
}
view_v2ray_error_log() {
	echo
	echo -e "$green Tekan Ctrl + C untuk keluar...$none"
	echo
	tail -f /var/log/v2ray/error.log
}
download_v2ray_config() {
	while :; do
		echo
		echo -e "$yellow 1. $none Unduh file konfigurasi klien V2Ray secara langsung (hanya dukungan Xshell)"
		echo
		echo -e "$yellow 2. $none Buat tautan unduhan file konfigurasi klien V2Ray"
		echo
		echo -e "$yellow 3. $none Buat tautan informasi konfigurasi V2Ray"
		echo
		echo -e "$yellow 4. $none Buat tautan kode QR konfigurasi V2Ray"
		echo
		read -p "$(echo -e "tolong pilih [${magenta}1-4$none]:")" other_opt
		if [[ -z $other_opt ]]; then
			error
		else
			case $other_opt in
			1)
				get_v2ray_config
				break
				;;
			2)
				get_v2ray_config_link
				break
				;;
			3)
				get_v2ray_config_info_link
				break
				;;
			4)
				get_v2ray_config_qr_link
				break
				;;
			*)
				error
				;;
			esac
		fi
	done
}
get_v2ray_config() {
	config
	echo
	echo " Jika klien SSH yang Anda gunakan saat ini bukan Xshell ... mengunduh file konfigurasi klien V2Ray akan menyebabkan pembekuan"
	echo
	while :; do
		read -p "$(echo -e "Jangan BB...Sedang digunakan Xshell [${magenta}Y$none]:")" is_xshell
		if [[ -z $is_xshell ]]; then
			error
		else
			if [[ $is_xshell == [yY] ]]; then
				echo
				echo "Mulai mengunduh .... Pilih lokasi penyimpanan file konfigurasi klien V2Ray"
				echo
				# sz /etc/v2ray/233blog_v2ray.zip
				local tmpfile="/tmp/233blog_v2ray_config_$RANDOM.json"
				cp -f $v2ray_client_config $tmpfile
				sz $tmpfile
				echo
				echo
				echo -e "$green Download selesai...$none"
				echo
				# echo -e "$yellow Mengekstrak kata sandi = ${cyan}233blog.com$none"
				# echo
				echo -e "$yellow SOCKS Pelabuhan mendengarkan = ${cyan}2333${none}"
				echo
				echo -e "${yellow} HTTP Pelabuhan mendengarkan = ${cyan}6666$none"
				echo
				echo "Tutorial klien V2Ray: https://233blog.com/post/20/"
				echo
				break
			else
				error
			fi
		fi
	done
	[[ -f $tmpfile ]] && rm -rf $tmpfile

}
get_v2ray_config_link() {
	echo
	echo -e "$green Menghasilkan link .... Tunggu sebentar.....$none"
	echo
	local random=$(echo $RANDOM-$RANDOM-$RANDOM | base64 -w 0)
	local link=$(curl -s --upload-file $v2ray_client_config "https://transfer.sh/${random}_233blog_v2ray.json")
	if [[ $link ]]; then
		echo
		echo "---------- Tautan file konfigurasi klien V2Ray -------------"
		echo
		echo -e "$yellow tautan = $cyan$link$none"
		echo
		echo -e "$yellow SOCKS Pelabuhan mendengarkan = ${cyan}2333${none}"
		echo
		echo -e "${yellow} HTTP Pelabuhan mendengarkan = ${cyan}6666$none"
		echo
		echo " V2Ray Tutorial klien: https://233blog.com/post/20/"
		echo
		echo "Catatan ... tautan akan kedaluwarsa dalam 14 hari"
		echo
		echo "Pengingat ... tolong jangan bagikan tautan ... kecuali Anda punya alasan khusus...."
		echo
	else
		echo
		echo -e "$red Ups ... ada yang tidak beres ... coba lagi $none"
		echo
	fi
}
create_v2ray_config_text() {

	get_transport_args

	echo
	echo
	echo "---------- Informasi konfigurasi V2Ray -------------"
	if [[ $v2ray_transport == "4" || $v2ray_transport == 16 ]]; then
		if [[ ! $caddy_installed ]]; then
			echo
			echo " peringatan! Harap konfigurasikan TLS sendiri ... tutorial: https://233blog.com/post/19/"
		fi
		echo
		echo "Host (Address) = ${domain}"
		echo
		echo "Port (Port) = 443"
		echo
		echo "identitas pengguna (User ID / UUID) = ${v2ray_id}"
		echo
		echo "ID ekstraID ekstra (Alter Id) = ${alterId}"
		echo
		echo "Protokol Transfer (Network) = ${net}"
		echo
		echo "Jenis kamuflase (header type) = ${header}"
		echo
		echo "Nama domain palsu (host) = ${domain}"
		echo
		echo "Jalan (path) = ${_path}"
		echo
		echo "TLS (Enable TLS) = nyalakan"
		echo
		if [[ $is_blocked_ad ]]; then
			echo " Catatan: Pemblokiran iklan diaktifkan.."
			echo
		fi
	else
		[[ -z $ip ]] && get_ip
		echo
		echo "Host (Address) = ${ip}"
		echo
		echo "Port (Port) = $v2ray_port"
		echo
		echo "identitas pengguna (User ID / UUID) = ${v2ray_id}"
		echo
		echo "ID ekstra (Alter Id) = ${alterId}"
		echo
		echo "Protokol Transfer (Network) = ${net}"
		echo
		echo "Jenis kamuflase (header type) = ${header}"
		echo
	fi
	if [[ $v2ray_transport -ge 9 || $v2ray_transport -le 15 ]] && [[ $is_blocked_ad ]]; then
		echo "Catatan: Port dinamis diaktifkan ... Pemblokiran iklan diaktifkan..."
		echo
	elif [[ $v2ray_transport -ge 9 || $v2ray_transport -le 15 ]]; then
		echo "Catatan: Port dinamis diaktifkan..."
		echo
	elif [[ $is_blocked_ad ]]; then
		echo "Catatan: Pemblokiran iklan diaktifkan.."
		echo
	fi
	echo "---------- END -------------"
	echo
	echo "Tutorial klien V2Ray: https://233blog.com/post/20/"
	echo
}
get_v2ray_config_info_link() {
	socks_check
	echo
	echo -e "$green Menghasilkan link .... Tunggu sebentar.....$none"
	echo
	create_v2ray_config_text >/tmp/233blog_v2ray.txt
	local random=$(echo $RANDOM-$RANDOM-$RANDOM | base64 -w 0)
	local link=$(curl -s --upload-file /tmp/233blog_v2ray.txt "https://transfer.sh/${random}_233blog_v2ray.txt")
	if [[ $link ]]; then
		echo
		echo "---------- Link informasi konfigurasi V2Ray-------------"
		echo
		echo -e "$yellow tautan = $cyan$link$none"
		echo
		echo -e " V2Ray Tutorial klien: https://233blog.com/post/20/"
		echo
		echo "Catatan ... tautan akan kedaluwarsa dalam 14 hari..."
		echo
		echo "Pengingat ... tolong jangan bagikan tautan ... kecuali Anda punya alasan khusus...."
		echo
	else
		echo
		echo -e "$red Ups ... ada yang tidak beres ... coba lagi $none"
		echo
	fi
	rm -rf /tmp/233blog_v2ray.txt
}
get_v2ray_config_qr_link() {

	socks_check
	create_vmess_URL_config

	echo
	echo -e "$green Menghasilkan link .... Tunggu sebentar.....$none"
	echo
	local vmess="vmess://$(cat /etc/v2ray/vmess_qr.json | tr -d '\n' | base64 -w 0)"
	echo $vmess | tr -d '\n' >/etc/v2ray/vmess.txt
	cat /etc/v2ray/vmess.txt | qrencode -s 50 -o /tmp/233blog_v2ray.png
	local random=$(echo $RANDOM-$RANDOM-$RANDOM | base64 -w 0)
	local link=$(curl -s --upload-file /tmp/233blog_v2ray.png "https://transfer.sh/${random}_233blog_v2ray.png")
	if [[ $link ]]; then
		echo
		echo "---------- Tautan kode QR V2Ray -------------"
		echo
		echo -e "$yellow Terapkan ke V2RayNG v0.4.1+ / Kitsunebi = $cyan$link$none"
		echo
		echo
		echo " V2Ray Tutorial klien: https://233blog.com/post/20/"
		echo
		echo "Catatan ... tautan akan kedaluwarsa dalam 14 hari"
		echo
		echo "Pengingat ... tolong jangan bagikan tautan ... kecuali Anda punya alasan khusus...."
		echo
	else
		echo
		echo -e "$red Oh ya ... ada yang tidak beres...$none"
		echo
		echo -e "Silakan coba gunakan ${cyan} v2ray qr ${none} diperbarui"
		echo
	fi
	rm -rf /tmp/233blog_v2ray.png
	# rm -rf /etc/v2ray/vmess_qr.json
	# rm -rf /etc/v2ray/vmess.txt
}
get_v2ray_vmess_URL_link() {
	socks_check
	create_vmess_URL_config
	local vmess="vmess://$(cat /etc/v2ray/vmess_qr.json | base64 -w 0)"
	echo
	echo "---------- V2Ray vmess URL / V2RayNG v0.4.1+ / V2RayN v2.1+ / Hanya cocok untuk beberapa klien -------------"
	echo
	echo -e ${cyan}$vmess${none}
	echo
	rm -rf /etc/v2ray/vmess_qr.json
}
other() {
	while :; do
		echo
		echo -e "$yellow 1. $none Install BBR"
		echo
		echo -e "$yellow 2. $none Pasang LotServer(Kecepatan tajam)"
		echo
		echo -e "$yellow 3. $none Copot pemasangan LotServer(Kecepatan tajam)"
		echo
		read -p "$(echo -e "请选择 [${magenta}1-3$none]:")" _opt
		if [[ -z $_opt ]]; then
			error
		else
			case $_opt in
			1)
				install_bbr
				break
				;;
			2)
				install_lotserver
				break
				;;
			3)
				uninstall_lotserver
				break
				;;
			*)
				error
				;;
			esac
		fi
	done
}
install_bbr() {
	local test1=$(sed -n '/net.ipv4.tcp_congestion_control/p' /etc/sysctl.conf)
	local test2=$(sed -n '/net.core.default_qdisc/p' /etc/sysctl.conf)
	if [[ $(uname -r | cut -b 1) -eq 4 ]]; then
		case $(uname -r | cut -b 3-4) in
		9. | [1-9][0-9])
			if [[ $test1 == "net.ipv4.tcp_congestion_control = bbr" && $test2 == "net.core.default_qdisc = fq" ]]; then
				local is_bbr=true
			else
				local try_enable_bbr=true
			fi
			;;
		esac
	fi
	if [[ $is_bbr ]]; then
		echo
		echo -e "$green BBR Sudah diaktifkan ... tidak perlu menginstal $none"
		echo
	elif [[ $try_enable_bbr ]]; then
		sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
		sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
		echo "net.ipv4.tcp_congestion_control = bbr" >>/etc/sysctl.conf
		echo "net.core.default_qdisc = fq" >>/etc/sysctl.conf
		sysctl -p >/dev/null 2>&1
		echo
		echo -e "$green ..Karena kernel kecil Anda mendukung BBR ... Pengoptimalan BBR telah diaktifkan untuk Anda....$none"
		echo
	else
		# https://teddysun.com/489.html
		bash <(curl -s -L https://github.com/teddysun/across/raw/master/bbr.sh)
	fi
}
install_lotserver() {
	# https://moeclub.org/2017/03/08/14/
	wget --no-check-certificate -qO /tmp/appex.sh "https://raw.githubusercontent.com/0oVicero0/serverSpeeder_Install/master/appex.sh"
	bash /tmp/appex.sh 'install'
	rm -rf /tmp/appex.sh
}
uninstall_lotserver() {
	# https://moeclub.org/2017/03/08/14/
	wget --no-check-certificate -qO /tmp/appex.sh "https://raw.githubusercontent.com/0oVicero0/serverSpeeder_Install/master/appex.sh"
	bash /tmp/appex.sh 'uninstall'
	rm -rf /tmp/appex.sh
}

open_port() {
	if [[ $1 != "multiport" ]]; then
		# if [[ $cmd == "apt-get" ]]; then
		iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport $1 -j ACCEPT
		iptables -I INPUT -m state --state NEW -m udp -p udp --dport $1 -j ACCEPT
		ip6tables -I INPUT -m state --state NEW -m tcp -p tcp --dport $1 -j ACCEPT
		ip6tables -I INPUT -m state --state NEW -m udp -p udp --dport $1 -j ACCEPT

		# iptables-save >/etc/iptables.rules.v4
		# ip6tables-save >/etc/iptables.rules.v6
		# else
		# 	firewall-cmd --permanent --zone=public --add-port=$1/tcp
		# 	firewall-cmd --permanent --zone=public --add-port=$1/udp
		# 	firewall-cmd --reload
		# fi
	else
		# if [[ $cmd == "apt-get" ]]; then
		local multiport="${v2ray_dynamic_port_start_input}:${v2ray_dynamic_port_end_input}"
		iptables -I INPUT -p tcp --match multiport --dports $multiport -j ACCEPT
		iptables -I INPUT -p udp --match multiport --dports $multiport -j ACCEPT
		ip6tables -I INPUT -p tcp --match multiport --dports $multiport -j ACCEPT
		ip6tables -I INPUT -p udp --match multiport --dports $multiport -j ACCEPT

		# iptables-save >/etc/iptables.rules.v4
		# ip6tables-save >/etc/iptables.rules.v6
		# else
		# 	local multi_port="${v2ray_dynamic_port_start_input}-${v2ray_dynamic_port_end_input}"
		# 	firewall-cmd --permanent --zone=public --add-port=$multi_port/tcp
		# 	firewall-cmd --permanent --zone=public --add-port=$multi_port/udp
		# 	firewall-cmd --reload
		# fi
	fi
	if [[ $cmd == "apt-get" ]]; then
		iptables-save >/etc/iptables.rules.v4
		ip6tables-save >/etc/iptables.rules.v6
	else
		service iptables save >/dev/null 2>&1
		service ip6tables save >/dev/null 2>&1
	fi

}
del_port() {
	if [[ $1 != "multiport" ]]; then
		# if [[ $cmd == "apt-get" ]]; then
		iptables -D INPUT -m state --state NEW -m tcp -p tcp --dport $1 -j ACCEPT
		iptables -D INPUT -m state --state NEW -m udp -p udp --dport $1 -j ACCEPT
		ip6tables -D INPUT -m state --state NEW -m tcp -p tcp --dport $1 -j ACCEPT
		ip6tables -D INPUT -m state --state NEW -m udp -p udp --dport $1 -j ACCEPT
		# else
		# 	firewall-cmd --permanent --zone=public --remove-port=$1/tcp
		# 	firewall-cmd --permanent --zone=public --remove-port=$1/udp
		# fi
	else
		# if [[ $cmd == "apt-get" ]]; then
		local ports="${v2ray_dynamicPort_start}:${v2ray_dynamicPort_end}"
		iptables -D INPUT -p tcp --match multiport --dports $ports -j ACCEPT
		iptables -D INPUT -p udp --match multiport --dports $ports -j ACCEPT
		ip6tables -D INPUT -p tcp --match multiport --dports $ports -j ACCEPT
		ip6tables -D INPUT -p udp --match multiport --dports $ports -j ACCEPT
		# else
		# 	local ports="${v2ray_dynamicPort_start}-${v2ray_dynamicPort_end}"
		# 	firewall-cmd --permanent --zone=public --remove-port=$ports/tcp
		# 	firewall-cmd --permanent --zone=public --remove-port=$ports/udp
		# fi
	fi
	if [[ $cmd == "apt-get" ]]; then
		iptables-save >/etc/iptables.rules.v4
		ip6tables-save >/etc/iptables.rules.v6
	else
		service iptables save >/dev/null 2>&1
		service ip6tables save >/dev/null 2>&1
	fi
}
update() {
	while :; do
		echo
		echo -e "$yellow 1. $none Perbarui program utama V2Ray"
		echo
		echo -e "$yellow 2. $none Perbarui skrip manajemen V2Ray"
		echo
		read -p "$(echo -e "Tolong pilih [${magenta}1-2$none]:")" _opt
		if [[ -z $_opt ]]; then
			error
		else
			case $_opt in
			1)
				update_v2ray
				break
				;;
			2)
				update_v2ray.sh
				exit
				break
				;;
			*)
				error
				;;
			esac
		fi
	done
}
update_v2ray() {
	[ -d /tmp/v2ray ] && rm -rf /tmp/v2ray
	mkdir -p /tmp/v2ray

	v2ray_tmp_file="/tmp/v2ray/v2ray.zip"
	v2ray_latest_ver="$(curl -s "https://api.github.com/repos/v2ray/v2ray-core/releases/latest?r=$RANDOM" | grep 'tag_name' | cut -d\" -f4)"
	if [[ $v2ray_ver != $v2ray_latest_ver ]]; then
		echo
		echo -e " $green Huh ... Ditemukan versi baru....Memperbarui Seakarang....... $none"
		echo
		v2ray_download_link="https://github.com/v2ray/v2ray-core/releases/download/$v2ray_latest_ver/v2ray-linux-${v2ray_bit}.zip"

		if ! wget --no-check-certificate -O "$v2ray_tmp_file" $v2ray_download_link; then
			echo -e "
			$red Gagal mengunduh file V2Ray .. Mungkin jaringan kecil Anda terlalu panas ... Coba perbarui lagi dan mungkin bisa diselesaikan $none
			" && exit 1
		fi

		unzip $v2ray_tmp_file -d "/tmp/v2ray/"
		mkdir -p /usr/bin/v2ray
		cp -f "/tmp/v2ray/v2ray-${v2ray_latest_ver}-linux-${v2ray_bit}/v2ray" "/usr/bin/v2ray/v2ray"
		chmod +x "/usr/bin/v2ray/v2ray"
		cp -f "/tmp/v2ray/v2ray-${v2ray_latest_ver}-linux-${v2ray_bit}/v2ctl" "/usr/bin/v2ray/v2ctl"
		chmod +x "/usr/bin/v2ray/v2ctl"
		# systemctl restart v2ray
		# service v2ray restart >/dev/null 2>&1
		do_service restart v2ray
		echo
		echo -e " $green Pembaruan berhasil ... Versi V2Ray saat ini: ${cyan}$v2ray_latest_ver$none"
		echo
		echo -e " $yellow Pengingat: Untuk menghindari masalah ... jadi versi V2Ray klien adalah yang terbaik: ${cyan}$v2ray_latest_ver$none"
		echo
		rm -rf /tmp/v2ray
	else
		echo
		echo -e " $green 木有发现新版本....$none"
		echo
	fi
}
update_v2ray.sh() {
	local latest_version=$(curl -s -L "https://raw.githubusercontent.com/233boy/v2ray/master/v2ray.sh?r=$RANDOM" | grep '_version' -m1 | cut -d\" -f2)
	if [[ $latest_version == $_version ]]; then
		echo
		echo -e "$green Versi baru tidak ditemukan $none"
		echo
	else
		echo
		echo -e " $green Huh ... Ditemukan versi baru....Perbarui Sekarang.......$none"
		echo
		cd /etc/v2ray/233boy/v2ray
		git pull
		cp -f /etc/v2ray/233boy/v2ray/v2ray.sh /usr/local/bin/v2ray
		chmod +x /usr/local/bin/v2ray
		echo
		echo -e "$green Pembaruan berhasil ... Versi skrip manajemen V2Ray saat ini: ${cyan}$latest_version$none"
		echo
	fi

}
uninstall_v2ray() {
	while :; do
		echo
		read -p "$(echo -e "Apakah akan mencopot pemasangan ${yellow}V2Ray$none [${magenta}Y/N$none]:")" uninstall_v2ray_ask
		if [[ -z $uninstall_v2ray_ask ]]; then
			error
		else
			case $uninstall_v2ray_ask in
			Y | y)
				is_uninstall_v2ray=true
				echo
				echo -e "$yellow Copot pemasangan V2Ray = ${cyan} Ya${none}"
				echo
				break
				;;
			N | n)
				echo
				echo -e "$red Copot pemasangan V2Ray ...$none"
				echo
				break
				;;
			*)
				error
				;;
			esac
		fi
	done

	if [[ $caddy_installed ]] && [[ -f /usr/local/bin/caddy && -f /etc/caddy/Caddyfile ]]; then
		while :; do
			echo
			read -p "$(echo -e "Apakah akan mencopot pemasangan ${yellow}Caddy$none [${magenta}Y/N$none]:")" uninstall_caddy_ask
			if [[ -z $uninstall_caddy_ask ]]; then
				error
			else
				case $uninstall_caddy_ask in
				Y | y)
					is_uninstall_caddy=true
					echo
					echo -e "$yellow Copot pemasangan Caddy = ${cyan} Ya {none}"
					echo
					break
					;;
				N | n)
					echo
					echo -e "$yellow Copot pemasangan Caddy = ${cyan} Tidak ${none}"
					echo
					break
					;;
				*)
					error
					;;
				esac
			fi
		done
	fi

	if [[ $is_uninstall_v2ray && $is_uninstall_caddy ]]; then
		pause
		echo

		if [[ $shadowsocks ]]; then
			del_port $ssport
		fi

		if [[ $v2ray_transport == "4" || $v2ray_transport == 16 ]]; then
			del_port "80"
			del_port "443"
			del_port $v2ray_port
		elif [[ $v2ray_transport -ge 9 && $v2ray_transport -le 15 ]]; then
			del_port $v2ray_port
			del_port "multiport"
		else
			del_port $v2ray_port
		fi

		[ $cmd == "apt-get" ] && rm -rf /etc/network/if-pre-up.d/iptables

		# [ $v2ray_pid ] && systemctl stop v2ray
		[ $v2ray_pid ] && do_service stop v2ray

		rm -rf /usr/bin/v2ray
		rm -rf /usr/local/bin/v2ray
		rm -rf /etc/v2ray
		rm -rf /var/log/v2ray

		# [ $caddy_pid ] && systemctl stop caddy
		[ $caddy_pid ] && do_service stop caddy

		rm -rf /usr/local/bin/caddy
		rm -rf /etc/caddy
		rm -rf /etc/ssl/caddy

		if [[ $systemd ]]; then
			systemctl disable v2ray >/dev/null 2>&1
			rm -rf /lib/systemd/system/v2ray.service
			systemctl disable caddy >/dev/null 2>&1
			rm -rf /lib/systemd/system/caddy.service
		else
			update-rc.d -f caddy remove >/dev/null 2>&1
			update-rc.d -f v2ray remove >/dev/null 2>&1
			rm -rf /etc/init.d/caddy
			rm -rf /etc/init.d/v2ray
		fi
		# clear
		echo
		echo -e "$green Penghapusan V2Ray selesai ....$none"
		echo
		echo "Jika menurut Anda skrip ini tidak cukup baik ... tolong beri tahu saya"
		echo
		echo "Pertanyaan umpan balik: https://github.com/233boy/v2ray/issues"
		echo

	elif [[ $is_uninstall_v2ray ]]; then
		pause
		echo

		if [[ $shadowsocks ]]; then
			del_port $ssport
		fi

		if [[ $v2ray_transport == "4" || $v2ray_transport == 16 ]]; then
			del_port "80"
			del_port "443"
			del_port $v2ray_port
		elif [[ $v2ray_transport -ge 9 && $v2ray_transport -le 15 ]]; then
			del_port $v2ray_port
			del_port "multiport"
		else
			del_port $v2ray_port
		fi

		[ $cmd == "apt-get" ] && rm -rf /etc/network/if-pre-up.d/iptables

		# [ $v2ray_pid ] && systemctl stop v2ray
		[ $v2ray_pid ] && do_service stop v2ray

		rm -rf /usr/bin/v2ray
		rm -rf /usr/local/bin/v2ray
		rm -rf /etc/v2ray
		rm -rf /var/log/v2ray
		if [[ $systemd ]]; then
			systemctl disable v2ray >/dev/null 2>&1
			rm -rf /lib/systemd/system/v2ray.service
		else
			update-rc.d -f v2ray remove >/dev/null 2>&1
			rm -rf /etc/init.d/v2ray
		fi
		# clear
		echo
		echo -e "$green Penghapusan V2Ray selesai ....$none"
		echo
		echo "Jika menurut Anda skrip ini tidak cukup baik ... tolong beri tahu saya"
		echo
		echo "Pertanyaan umpan balik: https://github.com/233boy/v2ray/issues"
		echo
	fi
}
config() {
	if [[ $shadowsocks ]]; then
		if [[ $is_blocked_ad ]]; then
			case $v2ray_transport in
			1)
				v2ray_server_config_file="/etc/v2ray/233boy/v2ray/config/blocked_hosts/server/tcp_ss.json"
				v2ray_client_config_file="/etc/v2ray/233boy/v2ray/config/client/tcp.json"
				;;
			2)
				v2ray_server_config_file="/etc/v2ray/233boy/v2ray/config/blocked_hosts/server/http_ss.json"
				v2ray_client_config_file="/etc/v2ray/233boy/v2ray/config/client/http.json"
				;;
			3)
				v2ray_server_config_file="/etc/v2ray/233boy/v2ray/config/blocked_hosts/server/ws_ss.json"
				v2ray_client_config_file="/etc/v2ray/233boy/v2ray/config/client/ws.json"
				;;
			4)
				v2ray_server_config_file="/etc/v2ray/233boy/v2ray/config/blocked_hosts/server/ws_ss.json"
				v2ray_client_config_file="/etc/v2ray/233boy/v2ray/config/client/ws_tls.json"
				;;
			5 | 6 | 7 | 8)
				v2ray_server_config_file="/etc/v2ray/233boy/v2ray/config/blocked_hosts/server/kcp_ss.json"
				v2ray_client_config_file="/etc/v2ray/233boy/v2ray/config/client/kcp.json"
				;;
			9)
				v2ray_server_config_file="/etc/v2ray/233boy/v2ray/config/blocked_hosts/server/tcp_ss_dynamic.json"
				v2ray_client_config_file="/etc/v2ray/233boy/v2ray/config/client/tcp.json"
				;;
			10)
				v2ray_server_config_file="/etc/v2ray/233boy/v2ray/config/blocked_hosts/server/http_ss_dynamic.json"
				v2ray_client_config_file="/etc/v2ray/233boy/v2ray/config/client/http.json"
				;;
			11)
				v2ray_server_config_file="/etc/v2ray/233boy/v2ray/config/blocked_hosts/server/ws_ss_dynamic.json"
				v2ray_client_config_file="/etc/v2ray/233boy/v2ray/config/client/ws.json"
				;;
			12 | 13 | 14 | 15)
				v2ray_server_config_file="/etc/v2ray/233boy/v2ray/config/blocked_hosts/server/kcp_ss_dynamic.json"
				v2ray_client_config_file="/etc/v2ray/233boy/v2ray/config/client/kcp.json"
				;;
			16)
				v2ray_server_config_file="/etc/v2ray/233boy/v2ray/config/blocked_hosts/server/h2_ss.json"
				v2ray_client_config_file="/etc/v2ray/233boy/v2ray/config/client/h2.json"
				;;
			17)
				v2ray_server_config_file="/etc/v2ray/233boy/v2ray/config/blocked_hosts/server/socks_ss.json"
				v2ray_client_config_file="/etc/v2ray/233boy/v2ray/config/client/socks.json"
				;;
			esac
		else
			case $v2ray_transport in
			1)
				v2ray_server_config_file="/etc/v2ray/233boy/v2ray/config/server/tcp_ss.json"
				v2ray_client_config_file="/etc/v2ray/233boy/v2ray/config/client/tcp.json"
				;;
			2)
				v2ray_server_config_file="/etc/v2ray/233boy/v2ray/config/server/http_ss.json"
				v2ray_client_config_file="/etc/v2ray/233boy/v2ray/config/client/http.json"
				;;
			3)
				v2ray_server_config_file="/etc/v2ray/233boy/v2ray/config/server/ws_ss.json"
				v2ray_client_config_file="/etc/v2ray/233boy/v2ray/config/client/ws.json"
				;;
			4)
				v2ray_server_config_file="/etc/v2ray/233boy/v2ray/config/server/ws_ss.json"
				v2ray_client_config_file="/etc/v2ray/233boy/v2ray/config/client/ws_tls.json"
				;;
			5 | 6 | 7 | 8)
				v2ray_server_config_file="/etc/v2ray/233boy/v2ray/config/server/kcp_ss.json"
				v2ray_client_config_file="/etc/v2ray/233boy/v2ray/config/client/kcp.json"
				;;
			9)
				v2ray_server_config_file="/etc/v2ray/233boy/v2ray/config/server/tcp_ss_dynamic.json"
				v2ray_client_config_file="/etc/v2ray/233boy/v2ray/config/client/tcp.json"
				;;
			10)
				v2ray_server_config_file="/etc/v2ray/233boy/v2ray/config/server/http_ss_dynamic.json"
				v2ray_client_config_file="/etc/v2ray/233boy/v2ray/config/client/http.json"
				;;
			11)
				v2ray_server_config_file="/etc/v2ray/233boy/v2ray/config/server/ws_ss_dynamic.json"
				v2ray_client_config_file="/etc/v2ray/233boy/v2ray/config/client/ws.json"
				;;
			12 | 13 | 14 | 15)
				v2ray_server_config_file="/etc/v2ray/233boy/v2ray/config/server/kcp_ss_dynamic.json"
				v2ray_client_config_file="/etc/v2ray/233boy/v2ray/config/client/kcp.json"
				;;
			16)
				v2ray_server_config_file="/etc/v2ray/233boy/v2ray/config/server/h2_ss.json"
				v2ray_client_config_file="/etc/v2ray/233boy/v2ray/config/client/h2.json"
				;;
			17)
				v2ray_server_config_file="/etc/v2ray/233boy/v2ray/config/server/socks_ss.json"
				v2ray_client_config_file="/etc/v2ray/233boy/v2ray/config/client/socks.json"
				;;
			esac
		fi
	else
		if [[ $is_blocked_ad ]]; then
			case $v2ray_transport in
			1)
				v2ray_server_config_file="/etc/v2ray/233boy/v2ray/config/blocked_hosts/server/tcp.json"
				v2ray_client_config_file="/etc/v2ray/233boy/v2ray/config/client/tcp.json"
				;;
			2)
				v2ray_server_config_file="/etc/v2ray/233boy/v2ray/config/blocked_hosts/server/http.json"
				v2ray_client_config_file="/etc/v2ray/233boy/v2ray/config/client/http.json"
				;;
			3)
				v2ray_server_config_file="/etc/v2ray/233boy/v2ray/config/blocked_hosts/server/ws.json"
				v2ray_client_config_file="/etc/v2ray/233boy/v2ray/config/client/ws.json"
				;;
			4)
				v2ray_server_config_file="/etc/v2ray/233boy/v2ray/config/blocked_hosts/server/ws.json"
				v2ray_client_config_file="/etc/v2ray/233boy/v2ray/config/client/ws_tls.json"
				;;
			5 | 6 | 7 | 8)
				v2ray_server_config_file="/etc/v2ray/233boy/v2ray/config/blocked_hosts/server/kcp.json"
				v2ray_client_config_file="/etc/v2ray/233boy/v2ray/config/client/kcp.json"
				;;
			9)
				v2ray_server_config_file="/etc/v2ray/233boy/v2ray/config/blocked_hosts/erver/tcp_dynamic.json"
				v2ray_client_config_file="/etc/v2ray/233boy/v2ray/config/client/tcp.json"
				;;
			10)
				v2ray_server_config_file="/etc/v2ray/233boy/v2ray/config/blocked_hosts/server/http_dynamic.json"
				v2ray_client_config_file="/etc/v2ray/233boy/v2ray/config/client/http.json"
				;;
			11)
				v2ray_server_config_file="/etc/v2ray/233boy/v2ray/config/blocked_hosts/server/ws_dynamic.json"
				v2ray_client_config_file="/etc/v2ray/233boy/v2ray/config/client/ws.json"
				;;
			12 | 13 | 14 | 15)
				v2ray_server_config_file="/etc/v2ray/233boy/v2ray/config/blocked_hosts/server/kcp_dynamic.json"
				v2ray_client_config_file="/etc/v2ray/233boy/v2ray/config/client/kcp.json"
				;;
			16)
				v2ray_server_config_file="/etc/v2ray/233boy/v2ray/config/blocked_hosts/server/h2.json"
				v2ray_client_config_file="/etc/v2ray/233boy/v2ray/config/client/h2.json"
				;;
			17)
				v2ray_server_config_file="/etc/v2ray/233boy/v2ray/config/blocked_hosts/server/socks.json"
				v2ray_client_config_file="/etc/v2ray/233boy/v2ray/config/client/socks.json"
				;;
			esac
		else
			case $v2ray_transport in
			1)
				v2ray_server_config_file="/etc/v2ray/233boy/v2ray/config/server/tcp.json"
				v2ray_client_config_file="/etc/v2ray/233boy/v2ray/config/client/tcp.json"
				;;
			2)
				v2ray_server_config_file="/etc/v2ray/233boy/v2ray/config/server/http.json"
				v2ray_client_config_file="/etc/v2ray/233boy/v2ray/config/client/http.json"
				;;
			3)
				v2ray_server_config_file="/etc/v2ray/233boy/v2ray/config/server/ws.json"
				v2ray_client_config_file="/etc/v2ray/233boy/v2ray/config/client/ws.json"
				;;
			4)
				v2ray_server_config_file="/etc/v2ray/233boy/v2ray/config/server/ws.json"
				v2ray_client_config_file="/etc/v2ray/233boy/v2ray/config/client/ws_tls.json"
				;;
			5 | 6 | 7 | 8)
				v2ray_server_config_file="/etc/v2ray/233boy/v2ray/config/server/kcp.json"
				v2ray_client_config_file="/etc/v2ray/233boy/v2ray/config/client/kcp.json"
				;;
			9)
				v2ray_server_config_file="/etc/v2ray/233boy/v2ray/config/server/tcp_dynamic.json"
				v2ray_client_config_file="/etc/v2ray/233boy/v2ray/config/client/tcp.json"
				;;
			10)
				v2ray_server_config_file="/etc/v2ray/233boy/v2ray/config/server/http_dynamic.json"
				v2ray_client_config_file="/etc/v2ray/233boy/v2ray/config/client/http.json"
				;;
			11)
				v2ray_server_config_file="/etc/v2ray/233boy/v2ray/config/server/ws_dynamic.json"
				v2ray_client_config_file="/etc/v2ray/233boy/v2ray/config/client/ws.json"
				;;
			12 | 13 | 14 | 15)
				v2ray_server_config_file="/etc/v2ray/233boy/v2ray/config/server/kcp_dynamic.json"
				v2ray_client_config_file="/etc/v2ray/233boy/v2ray/config/client/kcp.json"
				;;
			16)
				v2ray_server_config_file="/etc/v2ray/233boy/v2ray/config/server/h2.json"
				v2ray_client_config_file="/etc/v2ray/233boy/v2ray/config/client/h2.json"
				;;
			17)
				v2ray_server_config_file="/etc/v2ray/233boy/v2ray/config/server/socks.json"
				v2ray_client_config_file="/etc/v2ray/233boy/v2ray/config/client/socks.json"
				;;
			esac
		fi

	fi

	cp -f $v2ray_server_config_file $v2ray_server_config
	cp -f $v2ray_client_config_file $v2ray_client_config

	if [[ $shadowsocks ]]; then
		case $v2ray_transport in
		1)
			sed -i "28s/6666/$ssport/; 30s/chacha20-ietf/$ssciphers/; 31s/233blog.com/$sspass/" $v2ray_server_config
			;;
		2)
			sed -i "64s/6666/$ssport/; 66s/chacha20-ietf/$ssciphers/; 67s/233blog.com/$sspass/" $v2ray_server_config
			;;
		3 | 4)
			sed -i "31s/6666/$ssport/; 33s/chacha20-ietf/$ssciphers/; 34s/233blog.com/$sspass/" $v2ray_server_config
			;;
		5 | 6 | 7 | 8)
			sed -i "43s/6666/$ssport/; 45s/chacha20-ietf/$ssciphers/; 46s/233blog.com/$sspass/" $v2ray_server_config
			;;
		9)
			sed -i "31s/6666/$ssport/; 33s/chacha20-ietf/$ssciphers/; 34s/233blog.com/$sspass/; 42s/10000-20000/$port_range/" $v2ray_server_config
			;;
		10)
			sed -i "67s/6666/$ssport/; 69s/chacha20-ietf/$ssciphers/; 70s/233blog.com/$sspass/; 78s/10000-20000/$port_range/" $v2ray_server_config
			;;
		1[1-5])
			sed -i "34s/6666/$ssport/; 36s/chacha20-ietf/$ssciphers/; 37s/233blog.com/$sspass/; 45s/10000-20000/$port_range/" $v2ray_server_config
			;;
		16)
			sed -i "46s/6666/$ssport/; 48s/chacha20-ietf/$ssciphers/; 49s/233blog.com/$sspass/" $v2ray_server_config
			;;
		17)
			sed -i "30s/6666/$ssport/; 32s/chacha20-ietf/$ssciphers/; 33s/233blog.com/$sspass/" $v2ray_server_config
			;;
		esac

		case $v2ray_transport in
		6)
			sed -i "31s/none/utp/" $v2ray_server_config
			sed -i "44s/none/utp/" $v2ray_client_config
			;;
		7)
			sed -i "31s/none/srtp/" $v2ray_server_config
			sed -i "44s/none/srtp/" $v2ray_client_config
			;;
		8)
			sed -i "31s/none/wechat-video/" $v2ray_server_config
			sed -i "44s/none/wechat-video/" $v2ray_client_config
			;;
		13)
			sed -i "74s/none/utp/" $v2ray_server_config
			sed -i "44s/none/utp/" $v2ray_client_config
			;;
		14)
			sed -i "74s/none/srtp/" $v2ray_server_config
			sed -i "44s/none/srtp/" $v2ray_client_config
			;;
		15)
			sed -i "74s/none/wechat-video/" $v2ray_server_config
			sed -i "44s/none/wechat-video/" $v2ray_client_config
			;;
		esac

	else
		case $v2ray_transport in
		9)
			sed -i "31s/10000-20000/$port_range/" $v2ray_server_config
			;;
		10)
			sed -i "67s/10000-20000/$port_range/" $v2ray_server_config
			;;
		1[1-5])
			sed -i "34s/10000-20000/$port_range/" $v2ray_server_config
			;;
		esac

		case $v2ray_transport in
		6)
			sed -i "31s/none/utp/" $v2ray_server_config
			sed -i "44s/none/utp/" $v2ray_client_config
			;;
		7)
			sed -i "31s/none/srtp/" $v2ray_server_config
			sed -i "44s/none/srtp/" $v2ray_client_config
			;;
		8)
			sed -i "31s/none/wechat-video/" $v2ray_server_config
			sed -i "44s/none/wechat-video/" $v2ray_client_config
			;;
		13)
			sed -i "63s/none/utp/" $v2ray_server_config
			sed -i "44s/none/utp/" $v2ray_client_config
			;;
		14)
			sed -i "63s/none/srtp/" $v2ray_server_config
			sed -i "44s/none/srtp/" $v2ray_client_config
			;;
		15)
			sed -i "63s/none/wechat-video/" $v2ray_server_config
			sed -i "44s/none/wechat-video/" $v2ray_client_config
			;;
		esac

	fi

	if [[ $v2ray_transport == 17 ]]; then
		sed -i "8s/2333/$v2ray_port/; 14s/233blog/$username/; 15s/233blog.com/$userpass/" $v2ray_server_config
	else
		sed -i "8s/2333/$v2ray_port/; 14s/$old_id/$v2ray_id/; 16s/233/$alterId/" $v2ray_server_config
	fi
	if [[ $v2ray_transport -eq 16 ]]; then
		sed -i "24s/233blog.com/$domain/" $v2ray_server_config
		if [[ $is_path ]]; then
			sed -i "26s/233blog/$path/" $v2ray_server_config
		else
			sed -i "26s/233blog//" $v2ray_server_config
		fi
	fi

	[[ -z $ip ]] && get_ip
	if [[ $v2ray_transport -eq 4 || $v2ray_transport -eq 16 ]]; then
		sed -i "s/233blog.com/$domain/; 22s/2333/443/; 25s/$old_id/$v2ray_id/; 26s/233/$alterId/" $v2ray_client_config
		if [[ $is_path ]]; then
			sed -i "40s/233blog/$path/" $v2ray_client_config
		else
			sed -i "40s/233blog//" $v2ray_client_config
		fi
	elif [[ $v2ray_transport == 17 ]]; then
		sed -i "21s/233blog.com/$ip/; 22s/2333/$v2ray_port/; 25s/233blog/$username/; 26s/233blog.com/$userpass/" $v2ray_client_config
	else
		sed -i "s/233blog.com/$ip/; 22s/2333/$v2ray_port/; 25s/$old_id/$v2ray_id/; 26s/233/$alterId/" $v2ray_client_config
	fi

	# zip -q -r -j --password "233blog.com" /etc/v2ray/233blog_v2ray.zip $v2ray_client_config

	if [[ $v2ray_port == "80" ]]; then
		if [[ $cmd == "yum" ]]; then
			[[ $(pgrep "httpd") ]] && systemctl stop httpd >/dev/null 2>&1
			[[ $(command -v httpd) ]] && yum remove httpd -y >/dev/null 2>&1
		else
			[[ $(pgrep "apache2") ]] && service apache2 stop >/dev/null 2>&1
			[[ $(command -v apache2) ]] && apt-get remove apache2* -y >/dev/null 2>&1
		fi
	fi
	do_service restart v2ray
}
backup_config() {
	for keys in $*; do
		case $keys in
		v2ray_transport)
			sed -i "18s/=$v2ray_transport/=$v2ray_transport_opt/" $backup
			;;
		v2ray_port)
			sed -i "21s/=$v2ray_port/=$v2ray_port_opt/" $backup
			;;
		uuid)
			sed -i "24s/=$v2ray_id/=$uuid/" $backup
			;;
		alterId)
			sed -i "27s/=$alterId/=$new_alterId/" $backup
			;;
		v2ray_dynamicPort_start)
			sed -i "30s/=$v2ray_dynamicPort_start/=$v2ray_dynamic_port_start_input/" $backup
			;;
		v2ray_dynamicPort_end)
			sed -i "33s/=$v2ray_dynamicPort_end/=$v2ray_dynamic_port_end_input/" $backup
			;;
		domain)
			sed -i "36s/=$domain/=$new_domain/" $backup
			;;
		caddy)
			sed -i "39s/=/=true/" $backup
			;;
		+ss)
			sed -i "42s/=/=true/; 45s/=$ssport/=$new_ssport/; 48s/=$sspass/=$new_sspass/; 51s/=$ssciphers/=$new_ssciphers/" $backup
			;;
		-ss)
			sed -i "42s/=true/=/" $backup
			;;
		ssport)
			sed -i "45s/=$ssport/=$new_ssport/" $backup
			;;
		sspass)
			sed -i "48s/=$sspass/=$new_sspass/" $backup
			;;
		ssciphers)
			sed -i "51s/=$ssciphers/=$new_ssciphers/" $backup
			;;
		+ad)
			sed -i "54s/=/=true/" $backup
			;;
		-ad)
			sed -i "54s/=true/=/" $backup
			;;
		+path)
			sed -i "57s/=/=true/; 60s/=$path/=$new_path/; 63s#=$proxy_site#=$new_proxy_site#" $backup
			;;
		-path)
			sed -i "57s/=true/=/" $backup
			;;
		path)
			sed -i "60s/=$path/=$new_path/" $backup
			;;
		proxy_site)
			sed -i "63s#=$proxy_site#=$new_proxy_site#" $backup
			;;
		username)
			sed -i "66s/=$username/=$new_username/" $backup
			;;
		userpass)
			sed -i "69s/=$userpass/=$new_userpass/" $backup
			;;
		esac
	done

}
_boom_() {
	echo
	echo -e "$green ........... Kumpulan tautan konfigurasi V2Ray by Sshinjector.net  ..........$none"
	echo

	create_v2ray_config_text >/tmp/233blog_v2ray.txt

	create_vmess_URL_config

	local vmess="vmess://$(cat /etc/v2ray/vmess_qr.json | base64 -w 0)"
	echo $vmess >/etc/v2ray/vmess.txt
	cat /etc/v2ray/vmess.txt | qrencode -s 50 -o /tmp/233blog_v2ray.png

	local random1=$(echo $RANDOM-$RANDOM-$RANDOM | base64 -w 0)
	local random2=$(echo $RANDOM-$RANDOM-$RANDOM | base64 -w 0)
	local random3=$(echo $RANDOM-$RANDOM-$RANDOM | base64 -w 0)
	local link1=$(curl -s --upload-file $v2ray_client_config "https://transfer.sh/${random1}_233blog_v2ray.json")
	local link2=$(curl -s --upload-file /tmp/233blog_v2ray.txt "https://transfer.sh/${random2}_233blog_v2ray.txt")
	local link3=$(curl -s --upload-file /tmp/233blog_v2ray.png "https://transfer.sh/${random3}_233blog_v2ray.png")

	if [[ $link1 ]] && [[ $link2 && $link3 ]]; then
		echo -e "$yellow Tautan file konfigurasi klien: $cyan$link1$none"
		echo
		echo -e "$yellow Tautan informasi konfigurasi: $cyan$link2$none"
		echo
		echo -e "$yellow V2RayNG v0.4.1+ / Kitsunebi Tautan kode QR: $cyan$link3$none"
		echo
		echo "Tutorial klien V2Ray: https://233blog.com/post/20/"
		echo
	else
		echo
		echo -e "$red Ups ... terjadi sesuatu yang tidak terduga ... coba lagi.... $none"
		echo
	fi
	rm -rf /tmp/233blog_v2ray.txt
	rm -rf /etc/v2ray/vmess_qr.json
	rm -rf /etc/v2ray/vmess.txt
	rm -rf /tmp/233blog_v2ray.png

}

get_ip() {
	ip=$(curl -s ipinfo.io/ip)
}

error() {

	echo -e "\n$red kesalahan masukan！$none\n"

}

pause() {

	read -rsp "$(echo -e "Tekan $green Enter memasukkan $none Lanjutkan ... atau tekan $red Ctrl + C $none membatalkan.")" -d $'\n'
	echo
}
do_service() {
	if [[ $systemd ]]; then
		systemctl $1 $2
	else
		service $2 $1
	fi
}
_help() {
	echo
	echo "........... Informasi skrip manajemen V2Ray by Sshinjetor.net .........."
	echo -e "
	${green}v2ray menu $none Kelola V2Ray (setara dengan input v2ray)

	${green}v2ray info $none Lihat informasi konfigurasi V2Ray

	${green}v2ray config $none Ubah konfigurasi V2Ray

	${green}v2ray link $noneBuat tautan file konfigurasi klien V2Ray

	${green}v2ray textlink $none Buat tautan informasi konfigurasi V2Ray

	${green}v2ray qr $none Buat tautan kode QR konfigurasi V2Ray

	${green}v2ray ss $none Ubah konfigurasi Shadowsocks

	${green}v2ray ssinfo $none Lihat informasi konfigurasi Shadowsocks

	${green}v2ray ssqr $none Buat tautan kode QR konfigurasi Shadowsocks

	${green}v2ray status $none Melihat V2Ray status

	${green}v2ray start $none Start V2Ray

	${green}v2ray stop $none Stop V2Ray

	${green}v2ray restart $none Mulai ulang V2Ray

	${green}v2ray log $none Melihat V2Ray log

	${green}v2ray update $none Memperbarui V2Ray

	${green}v2ray update.sh $none Perbarui skrip manajemen V2Ray

	${green}v2ray uninstall $none Uninstall skrip manajemen V2Ray
"
}
menu() {
	clear
	while :; do
		echo
		echo "........... Script manajemen V2Ray $_version by Sshinjector.net .........."
		echo
		echo -e "## Versi V2Ray: $cyan$v2ray_ver$none  /  V2Ray status: $v2ray_status ##"
		echo -e "========================================="
		echo -e "$yellow 1. $none Lihat konfigurasi V2Ray"
		echo
		echo -e "$yellow 2. $none Ubah konfigurasi V2Ray"
		echo
		echo -e "$yellow 3. $none Unduh konfigurasi V2Ray / Buat tautan informasi konfigurasi / Buat tautan kode QR"
		echo
		echo -e "$yellow 4. $none Lihat konfigurasi Shadowsocks / buat tautan kode QR"
		echo
		echo -e "$yellow 5. $none Ubah konfigurasi Shadowsocks"
		echo
		echo -e "$yellow 6. $none Mulai / hentikan / mulai ulang / lihat log"
		echo
		echo -e "$yellow 7. $none Memperbarui V2Ray / Perbarui skrip manajemen V2Ray"
		echo
		echo -e "$yellow 8. $none Copot pemasangan V2Ray"
		echo
		echo -e "$yellow 9. $none lain"
		echo
		echo -e "Tips...Jika Anda tidak ingin menjalankan opsi...tekan $yellow Ctrl + C $none Untuk keluar"
		echo
		read -p "$(echo -e "Silakan pilih menu [${magenta}1-9$none]:")" choose
		if [[ -z $choose ]]; then
			exit 1
		else
			case $choose in
			1)
				view_v2ray_config_info
				break
				;;
			2)
				change_v2ray_config
				break
				;;
			3)
				download_v2ray_config
				break
				;;
			4)
				get_shadowsocks_config
				break
				;;
			5)
				change_shadowsocks_config
				break
				;;
			6)
				v2ray_service
				break
				;;
			7)
				update
				break
				;;
			8)
				uninstall_v2ray
				break
				;;
			9)
				other
				break
				;;
			*)
				error
				;;
			esac
		fi
	done
}
args=$1
[ -z $1 ] && args="menu"
case $args in
menu)
	menu
	;;
i | info)
	view_v2ray_config_info
	;;
c | config)
	change_v2ray_config
	;;
l | link)
	get_v2ray_config_link
	;;
L | infolink)
	get_v2ray_config_info_link
	;;
q | qr)
	get_v2ray_config_qr_link
	;;
s | ss)
	change_shadowsocks_config
	;;
S | ssinfo)
	view_shadowsocks_config_info
	;;
Q | ssqr)
	get_shadowsocks_config_qr_link
	;;
status)
	echo
	if [[ $v2ray_transport == "4" && $caddy_installed ]]; then
		echo -e " Status V2Ray: $v2ray_status  /  Status caddy: $caddy_run_status"
	else
		echo -e " Status V2Ray: $v2ray_status"
	fi
	echo
	;;
start)
	start_v2ray
	;;
stop)
	stop_v2ray
	;;
restart)
	[[ $v2ray_transport == "4" && $caddy_installed ]] && do_service restart caddy
	restart_v2ray
	;;
reload)
	config
	[[ $v2ray_transport == "4" && $caddy_installed ]] && caddy_config
	clear
	view_v2ray_config_info
	download_v2ray_config_ask
	;;
log)
	view_v2ray_log
	;;
url | URL)
	get_v2ray_vmess_URL_link
	;;
u | update)
	update_v2ray
	;;
U | update.sh)
	update_v2ray.sh
	exit
	;;
un | uninstall)
	uninstall_v2ray
	;;
reinstall)
	uninstall_v2ray
	if [[ $is_uninstall_v2ray ]]; then
		cd
		cd - >/dev/null 2>&1
		bash <(curl -s -L https://233blog.com/v2ray.sh)
	fi
	;;
233 | 2333 | 233boy | 233blog | 233blog.com)
	socks_check
	_boom_
	;;
[aA][Ii] | [Dd])
	socks_check
	change_v2ray_alterId
	;;
[aA][Ii][aA][Ii] | [Dd][Dd])
	socks_check
	custom_uuid
	;;
reuuid)
	socks_check
	backup_config uuid
	v2ray_id=$uuid
	config
	clear
	view_v2ray_config_info
	download_v2ray_config_ask
	;;
v | version)
	echo
	echo -e " Versi V2Ray saat ini: ${green}$v2ray_ver$none  /  Versi skrip manajemen V2Ray saat ini: ${cyan}$_version$none"
	echo
	;;
bbr)
	other
	;;
help | *)
	_help
	;;
esac
