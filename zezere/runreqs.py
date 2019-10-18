from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from django.urls import reverse

from . import models


AUTO_RUNREQS = {
    'fedora-iot-31': {
        "type": "ok",
        "compose_root": "https://kojipkgs.fedoraproject.org/compose/iot/latest-Fedora-IoT-31",
        "compose_name": "IoT",
    },
    'fedora-iot-32': {
        "type": "ok",
        "compose_root": "https://kojipkgs.fedoraproject.org/compose/iot/latest-Fedora-IoT-32",
        "compose_name": "IoT",
    },
}


def validate_runreq_autoid(autoid):
    if autoid not in AUTO_RUNREQS.keys():
        raise ValidationError(
            _("%(value)s is not a valid runreq autoid"),
            params={'value': autoid},
        )


def generate_auto_runreq(sender, instance, **kwargs):
    if not instance.auto_generated_id:
        # Nothing to auto-generate
        return
    info = AUTO_RUNREQS[instance.auto_generated_id]
    instance.type = info['type']
    compose_url = f"{info['compose_root']}/compose/{info['compose_name']}/:arch:/os"
    instance.kernel_url = f"{compose_url}/isolinux/vmlinuz"
    instance.kernel_cmd = f"inst.repo={compose_url} inst.ks=:urls.kickstart: inst.ks.sendmac inst.ks.sendsn noshell inst.cmdline inst.sshd=0 ip=dhcp"
    instance.initrd_url = f"{compose_url}/isolinux/initrd.img"


def replace_device_strings(request, value, device):
    value = value.replace(
        ":urls.kickstart:",
        request.build_absolute_uri(f'/netboot/kickstart/{device.mac_address}'),
    )
    value = value.replace(
        ":arch:",
        device.architecture,
    )

    return value


def generate_runreq_grubcfg(request, device, runreq):
    if runreq.type == models.RunRequest.TYPE_ONLINE_KERNEL:
        proxy_kernel_url = request.build_absolute_uri(
            f'/netboot/proxydl/{device.mac_address}/kernel')
        proxy_initrd_url = request.build_absolute_uri(
            f'/netboot/proxydl/{device.mac_address}/initrd')

        return replace_device_strings(request, f"""
linux {proxy_kernel_url} {runreq.kernel_cmd}
initrd {proxy_initrd_url}
boot
        """, device)

    elif runreq.type == models.RunRequest.TYPE_EFI:
        raise Exception("Build EFI app chainload")
        return ""

    else:
        raise Exception("Invalid runreq type")