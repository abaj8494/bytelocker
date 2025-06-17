bday = function(n){ bday=1; nm1 = n - 1
  for(j in 1:nm1){bday = bday*((365-j)/365)}
  bday <- 1 - bday; return(bday)}
