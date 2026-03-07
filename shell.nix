let
  pkgs = import <nixpkgs> {};
in
pkgs.mkShell {
  packages = [
    pkgs.python314
    pkgs.poetry
    pkgs.python314Packages.scapy
    pkgs.python314Packages.evdev
    pkgs.python314Packages.python-prctl 
    pkgs.cargo
    pkgs.rustc

    pkgs.rust-analyzer
    pkgs.rustfmt

    # If the dependencies need system libs, you usually need pkg-config + the lib
    pkgs.pkg-config
    pkgs.openssl
    pkgs.libpcap
    pkgs.gcc
    
  ];

  env = {
    RUST_BACKTRACE = "full";
     LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath [
      pkgs.stdenv.cc.cc
    ];
    POETRY_VIRTUALENVS_IN_PROJECT = "true";
    POETRY_VIRTUALENVS_PATH = "{project-dir}/.venv";

    POETRY_VIRTUALENVS_PREFER_ACTIVE_PYTHON = "true";


  };
}
  
  
  

  
  

