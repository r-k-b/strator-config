# Edit this configuration file to define what should be installed on
# your system.  Help is available in the configuration.nix(5) man page
# and in the NixOS manual (accessible by running ‘nixos-help’).

{ config, pkgs, ... }:

{
  imports = [ # Include the results of the hardware scan.
    ./hardware-configuration.nix
  ];

  # Use the systemd-boot EFI boot loader.
  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = true;

  nix = {
    package = pkgs.nixFlakes;
    extraOptions = ''
      experimental-features = nix-command flakes
    '';
  };

  networking.hostName = "nixos-strator"; # Define your hostname.
  # networking.wireless.enable = true;  # Enables wireless support via wpa_supplicant.

  # The global useDHCP flag is deprecated, therefore explicitly set to false here.
  # Per-interface useDHCP will be mandatory in the future, so this generated config
  # replicates the default behaviour.
  networking.useDHCP = false;
  networking.interfaces.enp0s31f6.useDHCP = true;
  networking.interfaces.enp3s0.useDHCP = true;
  networking.interfaces.wlp4s0.useDHCP = true;

  # Configure network proxy if necessary
  # networking.proxy.default = "http://user:password@proxy:port/";
  # networking.proxy.noProxy = "127.0.0.1,localhost,internal.domain";

  # Select internationalisation properties.
  i18n.defaultLocale = "en_US.UTF-8";
  console = {
    font = "Lat2-Terminus16";
    keyMap = "us";
  };

  # Set your time zone.
  time.timeZone = "Australia/Sydney";

  # List packages installed in system profile. To search, run:
  # $ nix search wget
  environment.systemPackages = with pkgs; [
    autojump
    autossh
    bind
    curl
    direnv
    fzf
    git
    mosh
    nixfmt
    stow
    tldr
    tmux
    vim
    wget
    xsel
  ];

  nixpkgs.config.allowUnfree = true;

  # Some programs need SUID wrappers, can be configured further or are
  # started in user sessions.
  # programs.mtr.enable = true;
  # programs.gnupg.agent = {
  #   enable = true;
  #   enableSSHSupport = true;
  #   pinentryFlavor = "gnome3";
  # };

  fileSystems."/mnt/blestion" = {
    device = "/dev/disk/by-label/blestion";
    fsType = "ext4";
  };

  fileSystems."/mnt/smiticia" = {
    device = "/dev/disk/by-label/smiticia";
    fsType = "ext4";
  };

  # List services that you want to enable:

  # Enable the OpenSSH daemon.
  services.openssh.enable = true;
  programs.mosh.enable = true;

  services.samba = {
    enable = true;
    securityType = "user";
    extraConfig = ''
      workgroup = WORKGROUP
      server string = smbnix
      netbios name = smbnix
      security = user 
      use sendfile = yes
      min protocol = smb2
      max protocol = smb2
      #hosts allow = 192.168.0  localhost
      #hosts deny = 0.0.0.0/0
      guest account = nobody
      map to guest = bad user
    '';
    shares = {
      blestion = {
        path = "/mnt/blestion";
        browseable = "yes";
        "read only" = "no";
        "guest ok" = "yes";
        #"create mask" = "0644";
        #"directory mask" = "0755";
        #"force user" = "username";
        #"force group" = "groupname";
      };
      smiticia = {
        path = "/mnt/smiticia";
        browseable = "yes";
        "read only" = "no";
        "guest ok" = "yes";
        #"create mask" = "0644";
        #"directory mask" = "0755";
        #"force user" = "username";
        #"force group" = "groupname";
      };
      #private = {
      #  path = "/mnt/Shares/Private";
      #  browseable = "yes";
      #  "read only" = "no";
      #  "guest ok" = "no";
      #  #"create mask" = "0644";
      #  #"directory mask" = "0755";
      #  #"force user" = "username";
      #  #"force group" = "groupname";
      #};
    };
  };

  services.transmission = {
    enable = true;
    openFirewall = true;
    settings = {
      download-dir = "/mnt/blestion/transmission/Downloads";
      incomplete-dir = "/mnt/blestion/transmission/.incomplete";
      incomplete-dir-enabled = true;
      message-level = 1;
      peer-port = 51413;
      peer-port-random-high = 65535;
      peer-port-random-low = 49152;
      peer-port-random-on-start = false;
      rpc-bind-address = "0.0.0.0";
      rpc-port = 9091;
      rpc-whitelist = "127.0.0.1,192.168.*.*";
      script-torrent-done-enabled = false;
      script-torrent-done-filename = "";
      umask = 2;
      utp-enabled = true;
      watch-dir = "/mnt/blestion/transmission/watchdir";
      watch-dir-enabled = false;
    };
  };

  # why does this show on https://search.nixos.org/options?channel=unstable&show=services.rtorrent.enable&from=0&size=50&sort=relevance&query=rtorrent
  # but not in `nixos-option services`?
  #services.rtorrent = {
  #  enable = true;
  #  openFirewall = true;
  #  dataDir = "/mnt/blestion/rtorrent_downloads";
  #};
  
  # Open ports in the firewall.
  # networking.firewall.allowedTCPPorts = [ ... ];
  # networking.firewall.allowedUDPPorts = [ ... ];
  networking = {
    firewall.allowedTCPPorts = [ 139 445 9091 ]; # 9091 is Transmission's Web interface
    firewall.allowedUDPPorts = [ 137 138 ];
    firewall.allowPing = true;
    nameservers = [
      "8.8.4.4"
      "8.8.8.8"
      "192.168.1.1"
    ];
  };
  # Or disable the firewall altogether.
  # networking.firewall.enable = false;

  # Enable CUPS to print documents.
  # services.printing.enable = true;

  # Enable sound.
  # sound.enable = true;
  # hardware.pulseaudio.enable = true;

  # Enable the X11 windowing system.
  # services.xserver.enable = true;
  # services.xserver.layout = "us";
  # services.xserver.xkbOptions = "eurosign:e";

  # Enable touchpad support.
  # services.xserver.libinput.enable = true;

  # Enable the KDE Desktop Environment.
  # services.xserver.displayManager.sddm.enable = true;
  # services.xserver.desktopManager.plasma5.enable = true;
  # https://github.com/NixOS/nixpkgs/issues/47201#issuecomment-423798284
  virtualisation.docker.enable = true;
      
  users.groups.docker = {};
   
  # Define a user account. Don't forget to set a password with ‘passwd’.
  users.users.rkb = {
    isNormalUser = true;
    extraGroups = [
      "docker"
      "transmission"
      "wheel" # Enable ‘sudo’ for the user.
    ];
    initialPassword = "hunter2";
  };

  # This value determines the NixOS release from which the default
  # settings for stateful data, like file locations and database versions
  # on your system were taken. It‘s perfectly fine and recommended to leave
  # this value at the release version of the first install of this system.
  # Before changing this value read the documentation for this option
  # (e.g. man configuration.nix or on https://nixos.org/nixos/options.html).
  system.stateVersion = "20.03"; # Did you read the comment?

  security.sudo.extraConfig = ''
    Defaults        timestamp_timeout=120
  '';
}
