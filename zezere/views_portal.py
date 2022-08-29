import requests

from django.core.exceptions import PermissionDenied
from django.contrib import messages
from django.db import transaction
from django.http import Http404, HttpResponseBadRequest
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST

from rules.contrib.views import permission_required
from ipware import get_client_ip

from zezere.models import Device, RunRequest, device_getter, SSHKey, FDOConfig


@login_required
def index(request):
    return render(request, "portal/index.html", {"nbar": "portal"})


@login_required
def claim(request):
    if request.method == "POST":
        with transaction.atomic():
            device = get_object_or_404(Device, mac_address=request.POST["mac_address"])
            if not request.user.has_perm(Device.get_perm("claim"), device):
                raise PermissionDenied()

            device.owner = request.user
            device.save()
        return redirect("/portal/claim/")

    if request.user.is_superuser:
        unclaimed = Device.objects.filter(owner__isnull=True)
    else:
        remote_ip, _ = get_client_ip(request)
        unclaimed = Device.objects.filter(owner__isnull=True, last_ip_address=remote_ip)
    context = {
        "unclaimed_devices": unclaimed,
        "super": request.user.is_superuser,
        "nbar": "claim",
    }
    return render(request, "portal/claim.html", context)


@login_required
def devices(request):
    devices = Device.objects.filter(owner=request.user)
    return render(
        request, "portal/devices.html", {"devices": devices, "nbar": "devices"}
    )


@permission_required(Device.get_perm("provision"), fn=device_getter)
def new_runreq(request, mac_addr):
    device = get_object_or_404(Device, mac_address=mac_addr.upper())

    if request.method == "POST":
        rrid = request.POST["runrequest"]
        runreq = get_object_or_404(RunRequest, id=rrid)
        if not request.user.has_perm(RunRequest.get_perm("use"), runreq):
            raise Http404()
        device.run_request = runreq
        device.full_clean()
        device.save()
        return redirect("portal_devices")

    runreqs = RunRequest.objects.filter(auto_generated_id__isnull=False)

    return render(request, "portal/runreq.html", {"device": device, "runreqs": runreqs})


@permission_required(Device.get_perm("provision"), fn=device_getter)
@require_POST
def clean_runreq(request, mac_addr):
    device = get_object_or_404(Device, mac_address=mac_addr.upper())

    if device.run_request is None:
        return HttpResponseBadRequest()

    device.run_request = None
    device.full_clean()
    device.save()
    return redirect("portal_devices")


@login_required
def sshkeys(request):
    sshkeys = SSHKey.objects.filter(owner=request.user)
    return render(
        request, "portal/sshkeys.html", {"sshkeys": sshkeys, "nbar": "sshkeys"}
    )


@login_required
@require_POST
def remove_ssh_key(request):
    keyid = request.POST["sshkey_id"]
    sshkey = get_object_or_404(SSHKey, id=keyid)
    if not request.user.has_perm(SSHKey.get_perm("delete"), sshkey):
        raise Http404()
    sshkey.delete()
    return redirect("portal_sshkeys")


@login_required
@require_POST
def add_ssh_key(request):
    keyval = request.POST["sshkey"].strip()
    if not keyval:
        return redirect("portal_sshkeys")

    key = SSHKey(owner=request.user, key=keyval)
    key.full_clean()
    key.save()
    return redirect("portal_sshkeys")


@login_required
def ov(request):
    return render(request, "portal/ownership_voucher.html", {"nbar": "ov"})


@login_required
@require_POST
def add_ov(request):
    OV_BASE_URL = FDOConfig.objects.get(owner=request.user).ov_base_url
    AUTH_TOKEN = FDOConfig.objects.get(owner=request.user).auth_token

    payload = None
    no_of_vouchers = request.POST["no_of_vouchers"]

    if request.POST.get("ov"):
        content_type = "application/x-pem-file"
        payload = request.POST["ov"].strip()
    elif request.FILES.getlist("ov_file"):
        content_type = "application/cbor"
        files = request.FILES.getlist("ov_file")
        payload = files[0].read()
        for f in files[1:]:
            payload += f.read()
    else:
        messages.error(request, "No ownership voucher provided")
        return redirect("portal_ov")

    url = OV_BASE_URL
    headers = {
        "X-Number-Of-Vouchers": no_of_vouchers,
        "Content-Type": content_type,
        "Authorization": f"Bearer {AUTH_TOKEN}",
    }

    try:
        response = requests.request("POST", url, headers=headers, data=payload)
    except requests.exceptions.RequestException as e:
        messages.error(request, "Error while adding ownership voucher: {}".format(e))
        return redirect("portal_ov")

    if response.status_code == 201:
        messages.success(request, "Ownership voucher added")
    else:
        error_code = response.json().get("error_code")
        messages.error(request, "Error adding ownership voucher: {}".format(error_code))

    return redirect("portal_ov")


@login_required
def configure(request):
    if request.method == "GET":
        config = FDOConfig.objects.filter(owner=request.user).first()
        auth_token = config.auth_token if config else ""
        ov_base_url = config.ov_base_url if config else ""
        return render(
            request,
            "portal/fdoconfigure.html",
            {"auth_token": auth_token, "ov_base_url": ov_base_url},
        )
    elif request.method == "POST":
        auth_token = request.POST.get("auth_token")
        ov_base_url = request.POST.get("ov_base_url")
        owner = request.user
        if not auth_token or not ov_base_url:
            messages.error(request, "Please fill in all fields")
            return redirect("portal_configure")

        config = FDOConfig.objects.filter(owner=owner).first()
        if config is None:
            config = FDOConfig(owner=owner)
        config.auth_token = auth_token
        config.ov_base_url = ov_base_url
        config.save()
        messages.success(request, "Configuration saved")
        return redirect("portal_configure")