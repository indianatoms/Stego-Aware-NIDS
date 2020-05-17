#inter arival time
type IAT: record {
     c: count;
     v: vector of interval;
     t: time;
};

function variance(vec: vector of interval){
	local sum : double = 0;
	local avg : double = 0;
	local var : double = 0;
	local vec2: vector of double;
	for (i in vec){
		sum += |vec[i]|;
	}
	avg = sum / |vec|;
	for (i in vec){
#		print |(|vec[i]|-avg)|;
		vec2[i] = |(|vec[i]|-avg)| * |(|vec[i]|-avg)|;
	}
	sum = 0;
	for (i in vec2){
#		 print vec2[i];
		 sum += vec2[i];
	}
	var = sum/|vec|;
	print "varinace: ",var;
}

function cheek_intervals(tab: table[addr] of IAT, address: addr){
	if(address in tab){
		if(network_time() - tab[address]$t < 2sec){
			tab[address]$v += network_time() - tab[address]$t;
		}
		tab[address]$t = network_time();
		tab[address]$c += 1;
		if(tab[address]$c > 10){
			local vo: vector of interval = sort(tab[address]$v, function(a: interval, b:interval): int {return a > b ? 1 : -1;} );
			for (i in vo){
				print "interval: ",|vo[i]|;
				if (i != |vo|-1){
#					print "delta: ",|vo[i]-vo[i+1]|;
#					print "devided ",|(|vo[i]-vo[i+1]|)/vo[i]|;
					if(|(|vo[i]-vo[i+1]|)/vo[i]| > 0.5){
						print "possible stego";
##Ograniczyć o wartości krańcowe
					}
				}
			}
			variance(tab[address]$v);
			tab[address]$c = 0;
			print "new set";
			tab[address]$v = vector();
		}
	}
	else{
		tab[address] = IAT($c = 0, $t = network_time(), $v = vector());
	}

}



