consider having binsec at
./BINSEC/binsec

:

mkdir BINSEC
cd BINSEC
git clone https://github.com/binsec/binsec
cd binsec

sudo apt install -y \
  build-essential \
  git \
  opam \
  zlib1g-dev \
  libgmp-dev \
  libffi-dev \
  pkg-config
opam init --bare
eval $(opam env)
opam switch create binsec --packages=ocaml-system
eval $(opam env --switch=binsec)
opam install dune
opam install . --deps-only
opam install qcheck

binsec is at 
file _build/default/src/main.exe
_build/default/src/main.exe: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=2c85c1bb330481359496179508e210a1e46c47ad, for GNU/Linux 3.2.0, with debug_info, not stripped

