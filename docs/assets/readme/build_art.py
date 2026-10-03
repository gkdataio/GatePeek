"""Original GKData README artwork. Requires Pillow; no network or project imports.

Run beside artwork.json to rebuild this repository's hero assets.
Use --stills for a fast layout check and --font-dir for a custom font directory.
"""
from pathlib import Path
import argparse
import json
import math
from functools import lru_cache
from PIL import Image, ImageDraw, ImageFont

BASE=Path(__file__).resolve().parent
BG='#090F12'; PANEL='#111C20'; GRID='#23353A'; MUTED='#9EB2AF'; WHITE='#F0F3E8'
S=2
FONT_DIR=Path('C:/Windows/Fonts')

@lru_cache(maxsize=60)
def font(size,kind='sans'):
    names={'sans':['segoeui.ttf','DejaVuSans.ttf'],'bold':['segoeuib.ttf','DejaVuSans-Bold.ttf'],'display':['ariblk.ttf','DejaVuSans-Bold.ttf'],'mono':['consola.ttf','DejaVuSansMono.ttf']}[kind]
    for directory in [FONT_DIR,Path('/usr/share/fonts/truetype/dejavu')]:
        for name in names:
            if (directory/name).exists():return ImageFont.truetype(str(directory/name),round(size*S))
    raise FileNotFoundError('Provide Arial/Segoe UI/Consolas or DejaVu fonts via --font-dir.')

class Art:
    def __init__(self,w,h,im=None):
        self.im=im if im is not None else Image.new('RGB',(w*S,h*S),BG)
        self.d=ImageDraw.Draw(self.im)
    def line(self,pts,fill=GRID,width=1):
        self.d.line([(round(x*S),round(y*S)) for x,y in pts],fill=fill,width=max(1,round(width*S)))
    def rect(self,b,fill=None,outline=None,width=1):
        self.d.rectangle(tuple(round(v*S) for v in b),fill=fill,outline=outline,width=max(1,round(width*S)))
    def poly(self,pts,fill=None,outline=GRID,width=1):
        p=[(round(x*S),round(y*S)) for x,y in pts]
        if fill:self.d.polygon(p,fill=fill)
        if outline:self.line(pts+[pts[0]],outline,width)
    def circle(self,x,y,r,fill=None,outline=None,width=1):
        self.d.ellipse(tuple(round(v*S) for v in [x-r,y-r,x+r,y+r]),fill=fill,outline=outline,width=max(1,round(width*S)))
    def text(self,x,y,value,size,fill=WHITE,kind='sans'):
        self.d.text((round(x*S),round(y*S)),value,font=font(size,kind),fill=fill,anchor='lt')
    def fit(self,x,y,value,size,max_width,fill=WHITE,kind='display'):
        while font(size,kind).getlength(value)>max_width*S:size-=1
        self.text(x,y,value,size,fill,kind)
    def finish(self):return self.im.resize((self.im.width//S,self.im.height//S),Image.Resampling.LANCZOS)

def background(c,mobile):
    w,h=(600,580) if mobile else (1120,400)
    a=Art(w,h);acc=c['accent']
    a.rect((.5,.5,w-1,h-1),outline='#314348')
    a.rect((0,0,5,54),fill=acc)
    a.line([(25,28),(37,28)],acc);a.line([(31,22),(31,34)],acc)
    a.text(46,21,'GKDATA / PUBLIC WORK',13,acc,'mono')
    a.text(w-139,21,c['index']+' / '+c['category'],11,MUTED,'mono')
    a.line([(24,53),(w-24,53)])
    top=85 if mobile else (111 if len(c['title'])==1 else 88)
    size=(50 if len(c['title'])>1 else 76) if mobile else c['size']
    for i,title in enumerate(c['title']):
        a.fit(30 if mobile else 38,top+i*(size+8),title,size,535 if mobile else 670)
    subtitle_y=top+len(c['title'])*(size+8)+15
    a.fit(33 if mobile else 42,subtitle_y,c['subtitle'],18 if mobile else 22,535 if mobile else 656,MUTED,'sans')
    if mobile:cx,cy=300,372;bottom=522
    else:cx,cy=906,203;bottom=335
    for x in range(round(cx-153),round(cx+154),20):
        for y in range(round(cy-101),round(cy+102),20):a.rect((x,y,x+.6,y+.6),fill=GRID)
    # Registration marks give the art a quiet engineering-drawing frame.
    for x,sgn in [(cx-161,1),(cx+161,-1)]:
        a.line([(x,cy-112),(x+11*sgn,cy-112)],MUTED)
        a.line([(x,cy-112),(x,cy-101)],MUTED)
        a.line([(x,cy+112),(x+11*sgn,cy+112)],MUTED)
        a.line([(x,cy+112),(x,cy+101)],MUTED)
    a.line([(24,bottom),(w-24,bottom)])
    tags=c['tags'];gap=(w-64)/3
    for i,tag in enumerate(tags):
        x=32+i*gap
        a.text(x,bottom+23,f'0{i+1}',12,acc,'mono')
        a.fit(x+29,bottom+21,tag,13 if mobile else 15,gap-34,WHITE,'mono')
    return a.im,cx,cy

def draw_diagram(a,c,cx,cy,p):
    acc=c['accent'];kind=c['motif'];t=p*math.tau
    def pt(x,y):return cx+x,cy+y
    def line(points,color=GRID,w=1):a.line([pt(x,y) for x,y in points],color,w)
    def rect(b,fill=None,outline=GRID,w=1):a.rect((cx+b[0],cy+b[1],cx+b[2],cy+b[3]),fill,outline,w)
    def text(x,y,s,size=12,color=MUTED):a.text(cx+x,cy+y,s,size,color,'mono')
    def poly(points,fill=PANEL,outline=GRID,w=1):a.poly([pt(x,y) for x,y in points],fill,outline,w)
    def circle(x,y,r,fill=None,outline=GRID,w=1):a.circle(cx+x,cy+y,r,fill,outline,w)
    if kind=='headers':
        rect((-119,-78,119,78),PANEL,'#4D676A');line([(-119,-44),(119,-44)])
        for x in [-101,-87,-73]:circle(x,-61,2,acc,None)
        text(27,-67,'REQUEST',10)
        for y,length in [(-22,128),(0,90),(22,151)]:
            line([(-91,y),(-91+length,y)],'#496261',2)
        rect((-100,37,101,64),BG,acc)
        text(-89,45,'X-Bug-Bounty',12,acc)
        x=-147+294*p
        for y in [-97,0]:
            line([(-150,y),(150,y)],'#1D3033')
            rect((x-9,y-2,x+9,y+2),acc,None)
        text(-83,90,'IDENTIFY YOUR TRAFFIC',10)
    elif kind=='layers':
        for i in range(3):
            y=45-i*(40+5*math.sin(t))
            diamond=[(-120,y),(0,y-55),(120,y),(0,y+55)]
            poly(diamond,PANEL,acc if i==int(p*3)%3 else '#4E6969',1.5)
            for k in [.25,.5,.75]:
                line([(-120+120*k,y-55*k),(120*k,y+55-55*k)],'#2B464A')
                line([(-120+120*k,y+55*k),(120*k,y-55+55*k)],'#2B464A')
            circle(0,y,3,acc,None)
        text(-100,100,'TECH / VERSION / CATEGORY',10)
    elif kind=='library':
        offset=4*math.sin(t)
        for i in range(3):
            x=-112+i*56;y=-69+i*10+offset*(i-1)
            rect((x,y,x+118,y+124),PANEL,'#466163')
            rect((x+13,y+15,x+31,y+33),acc if i==int(p*3)%3 else '#334B4D',None)
            for j,length in enumerate([81,70,81,48]):line([(x+13,y+48+j*12),(x+13+length,y+48+j*12)],'#647D79')
        y=92;line([(-111,y),(119,y)],'#476465')
        x=-111+230*p;circle(x,y,4,acc,None)
        for x in [-111,4,119]:circle(x,y,3,BG,acc)
        text(-134,111,'SOURCE',10);text(-16,111,'REPORT',10);text(99,111,'JSON',10)
    elif kind=='network':
        nodes=[(-127,-64),(-132,2),(-113,74),(-51,-27),(12,8),(44,-82),(96,-34),(128,33),(69,87)]
        edges=[(0,3),(1,3),(2,4),(3,4),(4,5),(4,6),(4,7),(7,8),(6,7)]
        for i,j in edges:line([nodes[i],nodes[j]],'#3D6264')
        for i,j in edges:
            u=(p+(i+j)/19)%1;x=nodes[i][0]*(1-u)+nodes[j][0]*u;y=nodes[i][1]*(1-u)+nodes[j][1]*u
            circle(x,y,2,acc,None)
        for i,(x,y) in enumerate(nodes):
            circle(x,y,6 if i!=4 else 13,BG,acc if i==4 else '#739894')
            if i==4:circle(x,y,4,acc,None)
        text(-65,105,'SOURCES / CONTEXT',10)
    elif kind=='directory':
        rect((-125,-89,125,90),PANEL,'#456062')
        text(-108,-72,'PATH',11,acc);text(56,-72,'HTTP',11,acc)
        line([(-125,-45),(125,-45)])
        for i,(status,ln) in enumerate([('200',70),('301',92),('404',56),('200',84)]):
            y=-27+i*28;active=i==int(p*4)%4
            if active:rect((-120,y-5,120,y+16),'#1B3234',None)
            line([(-107,y+4),(-107+ln,y+4)],acc if active else '#456465',2)
            text(59,y-2,status,12,acc if active else MUTED)
        text(-71,105,'RESPONSE SNAPSHOT',10)
    elif kind=='pixels':
        phase=(1-math.cos(t))/2
        for r in range(7):
            for col in range(9):
                n=r*9+col
                x=-107+col*25;y=-81+r*25
                v=(n*17+31)%63
                xx=-107+(v%9)*25;yy=-81+(v//9)*25
                x=x+(xx-x)*phase;y=y+(yy-y)*phase
                bright=((r+col*2)%4)==0
                rect((x,y,x+16,y+16),acc if bright else '#2D4547',None)
        text(-85,105,'TEXT / SHUFFLE / IMAGE',10)
    elif kind=='learning':
        for i in range(3):
            x=-121+i*83;y=-64+8*math.sin(t+i*.9)
            rect((x,y,x+75,y+119),PANEL,acc if i==int(p*3)%3 else '#4A6768')
            text(x+12,y+13,'0'+str(i+1),11,acc)
            for j,s in enumerate(['{ }','[ ]','( )']):
                if i==j:text(x+15,y+45,s,25,WHITE)
            line([(x+13,y+98),(x+61,y+98)],'#536F6D')
        text(-78,97,'READ. TRY. UNDERSTAND.',10)

def render(c,base,cx,cy,p):
    a=Art(0,0,base.copy());draw_diagram(a,c,cx,cy,p);return a.finish()

def main():
    global FONT_DIR
    parser=argparse.ArgumentParser();parser.add_argument('--stills',action='store_true');parser.add_argument('--font-dir',type=Path,default=FONT_DIR)
    args=parser.parse_args();FONT_DIR=args.font_dir
    c=json.loads((BASE/'artwork.json').read_text(encoding='utf-8'))
    for mobile in [False,True]:
        stem='hero-mobile' if mobile else 'hero';base,cx,cy=background(c,mobile)
        still=render(c,base,cx,cy,.15);still.save(BASE/f'{stem}-static.png',optimize=True)
        if args.stills:continue
        palette=still.quantize(colors=128,method=Image.Quantize.MEDIANCUT)
        frames=[render(c,base,cx,cy,i/72).quantize(palette=palette,dither=Image.Dither.NONE) for i in range(72)]
        frames[0].save(BASE/f'{stem}.gif',save_all=True,append_images=frames[1:],duration=80,loop=0,optimize=True,disposal=1)
        print(f'{c["name"]}: {stem}.gif {(BASE/f"{stem}.gif").stat().st_size:,} bytes')

if __name__=='__main__':main()
