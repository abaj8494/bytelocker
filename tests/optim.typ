#import "@preview/drafting:0.2.2": *
#import "@preview/thmbox:0.2.0": *
#import "@preview/marge:0.1.0": sidenote
#import "@preview/hydra:0.6.1": hydra

#show math.equation.where(block: false): it => box(
  it,            // keep the original math
  height: auto,
  // debug:
  //fill: red, 
  //stroke: blue
)
//#show math.equation.where(block: false): math.equation.with(block: true)
#show: thmbox-init(counter-level: 2)

#let def-counter = counter("def")
#show: sectioned-counter(def-counter, level: 3)

#let defbox = note.with(
  numbering: "1.1.1",
  counter: def-counter,          
  fill: rgb("#f8f8f8"),
  border: (paint: rgb("#787878"), thickness: 0.8pt),
  radius: 3pt,
  inset: (x: 0.8em, y: 0.6em),
)

#let iff = $<==>$
#let imp = $==>$
#let ve(body) = {
  $op(upright(bold(body)))$
}
#let abs(body) = $bar.v #body bar.v$
#let norm(body, p: none) = {
  if p == none {
    $bar.v.double #body bar.v.double$
  } else {
    $bar.v.double #body bar.v.double_(#p)$
  }
}
#let scr(it) = text(
  features: ("ss01",),
  box($cal(it)$),
)

#show math.equation: set text(14pt)
#set text( size: 14pt )

#show: thmbox-init()

#set document(title: "Convex and Non-Convex Optimisation", author: "Aayush Bajaj")

#align(center)[
  #v(2em)
  #block(text(weight: "bold", size: 24pt)[Convex and Non-Convex Optimisation])
  #v(2em)
  #text(weight: "bold", size: 20pt)[Aayush Bajaj]
  #v(1em)
  #text(size: 16pt)[Version 2.7]
  #v(1em)
  #text(size: 16pt)[#datetime.today().display()]
  #v(4em)
  #image("crest.svg", width: 90%)
]

#pagebreak()
#set page(
  numbering: "1",
)

#outline(title: "Table of Contents")

#pagebreak()

#set heading(numbering:"1.")
#set math.equation(numbering: "(1)")
#set page(
  header: context{
    align(left, emph(hydra(1)))
  }
)

#v(-0.4cm)
= Mathematical Background
#v(-1.0cm)
#hide([#heading(outlined: false, depth: 2)[Hidden]])
#definition(
  title: "Mathspeak"
)[
  #defbox(
  variant: "Axiom"
)[A foundational statement accepted without proof. All other results are built ontop.] #defbox( variant: "Proposition")[ A proved statement that is less central than a theorem, but still of interest. ] #defbox( variant: "Lemma")[ A ``helper'' proposition proved to assist in establishing a more important result. ] #defbox( variant: "Corollary")[ A statement following from a theorem or proposition, requiring little to no extra proof. ] #defbox( variant: "Definition")[ A precise specification of an object, concept or notation. ] #defbox( variant: "Theorem")[ A non-trivial mathematical statement proved on the basis of axioms, definitions and earlier results. ] #defbox( variant: "Remark")[ An explanatory or clarifying note that is not part of the formal logical chain but gives insight / context. ] #defbox( variant: "Claim / Conjecture")[ A statement asserted that requires a proof. ] ]

//#set enum(numbering: "a)")
#definition(
  title: "Vector Norm"
)[
  A vector norm on $RR^n$ is a function $norm(dot.c)$ from $RR^n$ to $RR$ such that:

  + $norm(ve(x)) gt.eq 0,thin forall ve(x) in RR^n$ and $norm(ve(x)) = 0 iff ve(x) = ve(0)$ 
  + $norm(ve(x)+ve(y)) lt.eq norm(ve(x))+norm(ve(y))$ $forall ve(x),ve(y) in RR^n$ (Triangle Inequality)
  + $norm(alpha ve(x)) = |alpha| norm(ve(x))$ $forall alpha in RR, ve(x) in RR^n$
]

// repeat the above definition for the norm of a function.

#definition(
  title: "Continuous Derivatives"
)[
  The notation $ f in C^k ( RR^n) $
  means that the function $f: RR^n arrow.r RR$ possesses continuous derivatives up to order $k$ on $RR^n$.

  #example()[
    + $f in C^1 (RR^n)$ implies each $(partial f)/(partial x_i)$ exists, and $nabla f(x)$ is continuous on $RR^n$
    + $f in C^2 (RR^n)$ implies each $(partial f^2)/(partial x_i y_i)$ exists, and $nabla^2 f(x)$ forms a continuous Hessian matrix.
  ]
]

#theorem(
  title: "Cauchy Shwarz-Inequality"
)[
  $
    abs(ve(x)^T ve(y)) lt.eq norm(ve(x), p:2) norm(ve(y), p:2)
  $
]

#definition(
  title: "Closed and Bounded Sets"
)[
  A set $Omega subset RR^n$ is _closed_ if it contains all the limits of convergent sequences of points in $Omega$.

  A set $Omega subset RR^n$ is _bounded_ if $exists K in RR^+$ for which $Omega subset B[0,K]$, where $B[0,K] = {ve(x) in RR^n : norm(ve(x)) lt.eq K}$ is the ball with centre 0.
]

#definition(
  title: "Standard Vector Function Forms"
)[
  If $f_0 in RR, ve(g) in RR^n, G in R^{n times n}$:
  + Linear: $f(ve(x)) = ve(g)^T ve(x)$
  + Affine: $f(ve(x)) = ve(g)^T ve(x) + f_0$
  + Quadratic: $f(ve(x)) = 1/2 ve(x)^T G ve(x) + ve(g)^T ve(x) + f_0$
]

#definition(
  title: "Symmetric"
)[
  Let $A in RR^(n times n)$ be a symmetric matrix. Then:
  + $A$ has $n$ real eigenvalues.
  + There exists an orthogonal matrix $Q$ #margin-note(side: left)[$script(Q^top Q=I)$] such that $A= Q D Q^top$ where $D=op("diag")(lambda_1,dots.h,lambda_n)$ and $Q=[v_1 thin dots.h thin v_n]$ with $v_i$ an eigenvector of $A$ corresponding to eigenvalue $lambda_i$.
  + $op("det")(A)=product_(i=1)^n lambda_i$ and $op("tr")(A)=sum_(i=1)^n lambda_i=sum_(i=1)^n A_(i i)$.
  + $A$ is positive definite $iff lambda_i>0$ for all $i=1,dots.h,n$.
  + $A$ is positive semi-definite $iff lambda_i gt.eq 0$ for all $i=1,dots.h,n$.
  + $A$ is indefinite $iff$ there exist $i,j$ with $lambda_i>0$ and $lambda_j<0$.
]

#definition(
  title: "Leading Principal Minors / Sylvester's Criterion"
)[
  A symmetric matrix $A$ is *positive definite* if and only if all leading principal minors of A are positive. The $i$th principal minor $Delta_i$ of A is the determinant of the leading $i times i$ submatrix of A. 

  If $Delta_i, i = 1, 2, dots.h, n$ has the sign of $(-1)^i, i = 1, 2, dots.h, n$, that is, the values of $Delta_i$ are alternatively negative and positive, then $A$ is *negative definite*.

  *Note* that _PSD_ only applies if you check *all* principal minors, of which there are $2^n - 1$, as opposed to just checking $n$ submatrices here.
]

#pagebreak()
= Convexity

#definition(
  title: "Convex"
)[
  A set $Omega subset.eq RR^n$ is convex $iff theta ve(x) + (1-theta) ve(y) in Omega$ for all $theta in[0,1]$ and for all $ve(x),ve(y) in Omega$.

  #note[ there is no such thing as a _concave_ set]
]

#proposition(
  title: "Intersection of Convex Sets"
)[Let $Omega_1, dots.h, Omega_n subset.eq RR^n$ be convex, then their intersections $Omega = Omega_1 inter dots.h inter Omega_n $ is convex.]

#definition(
  title: "Extreme Points"
)[
  Let $Omega subset.eq RR^n$ be a convex set $macron(ve(x)) in Omega$ is an extreme point of $Omega iff ve(x), ve(y) in Omega, thin theta in [0,1]$ and $macron(ve(x)) = theta ve(x) + (1 - theta) y imp ve(x), ve(y) in RR$, or $ve(x) = ve(y)$.

  In other words, a point is in an extreme point if it cannot be on a line segment in $Omega$.

  #align(center)[ #image("extreme.svg", width: 70%) ]

]

#definition(
  title: "Convex Combination"
)[
  The convex combination of $ve(x)^((1)), dots.h, ve(x)^((m)) in RR^m$ is
  $
    ve(x) = sum^m_(i=1) alpha_i ve(x)^((i)), " where " sum^m_(i=0)alpha_i = 1 " and " alpha_i gt.eq 0, i= 1, dots.h, m
  $
]

#definition(
  title: "Convex Hull"
)[
  The convex hull $op("conv")(Omega)$ of a set $Omega$ is the set of all convex combinations of points in $Omega$.
]

#theorem(
  title: "Separating Hyperplane",
  color: red
)[
  Let $Omega subset.eq RR^n$ be a non-empty closed convex set and let $z in.not Omega$. There exists a hyperplane $H = {ve(u) in RR^n: ve(a)^T ve(u) = beta}$ such that $ve(a)^T ve(z) lt beta$ and $ve(a)^T ve(x) gt.eq beta$ for all $x in Omega$.

  #image("sep-hyper.svg")
]

#definition(
  title: "Convex / Concave Functions"
)[
A function $f: Omega -> RR$ (with $Omega$ convex) is
- *convex* if $f(theta ve(x) + (1 - theta)ve(y)) <= theta f(ve(x)) + (1 - theta)f(ve(y))$;
- *strictly convex* if strict inequality holds whenever $ve(x) != ve(y)$;
- *concave* if $-f$ is convex.
]

#proposition(
  title: "Continous Differentiability of Convex Fn"
)[
  Let $Omega$ be a convex set and let $f: Omega -> RR$ be continuously differentiable on $Omega$. Then $f$ is convex over $Omega iff, forall x, y in Omega$, $ f(y) - f(x) >=& (y - x)^top nabla f(x) \ =& nabla f(x)^top (y-x) $ 
]

#pagebreak()
= Unconstrained Optimisation

#definition(
  title: "Standard Form"
)[ $ op("minimise", limits: #true)_(ve(x) in Omega) f(ve(x)) $
#remark[ $ max f(ve(x)) = -min{-f(ve(x))} $ ]
]

#definition(
  title: "Hessian"
)[
  $f: RR^n arrow.r RR$ be twice continuously differentiable. The Hessian $nabla^2 f : RR^n arrow.r RR^(n times n)$ of $f$ at $x$ is
  $
    nabla^2 f(x)=mat(
      (partial^2 f(x))/(partial x_1^2) , (partial^2 f(x))/(partial x_1 partial x_2) , dots.h , (partial^2 f(x))/(partial x_1 partial x_n) ;
      (partial^2 f(x))/(partial x_2 partial x_1) , (partial^2 f(x))/(partial x_2^2) , dots.h , (partial^2 f(x))/(partial x_2 partial x_n) ;
      dots.v , dots.v , dots.down , dots.v ;
      (partial^2 f(x))/(partial x_n partial x_1) , (partial^2 f(x))/(partial x_n partial x_2) , dots.h , (partial^2 f(x))/(partial x_n^2); delim: "["
    )
  $
]

#theorem(
  title: "First order necessary conditions"
)[
  If $x^*$ is a local minimizer and $f in C^1(RR^n)$ then $nabla f(x^*) = 0$.
]

#definition(
  title: "(Unconstrained) Stationary point"
)[
  $x^*$ is an unconstrained stationary point $iff nabla f(x^*)=0$
  #example()[local min, local max, saddle point.]
]

#definition(
  title: "Saddle point"
)[
  A stationary point $ve(x^*) in RR^n$ is a saddle point of $f$ if for any $delta gt 0$ there exist $ve(x), ve(y)$ with $norm(ve(x)-ve(x^*)) lt delta$, $norm(ve(y)-ve(x^*)) lt delta$ such that:
  $
  f(ve(x)) lt f(ve(x^*)) " and " f(ve(y)) gt f(ve(x^*))
  $
]

#proposition(
  title: "Second order necessary conditions"
)[
  If $f in C^2(RR^n)$ then
  + Local minimiser $imp nabla f(ve(x)^*)=0$ and $nabla^2 f(ve(x)^*)$ positive semi-definite.
  + Local maximiser $imp nabla f(ve(x)^*)=0$ and $nabla^2 f(ve(x)^*)$ negative semi-definite.

#corollary( title: "Local maximiser")[$macron(ve(x))$ is a local maximiser $imp nabla f(macron(ve(x))) = ve(0)$ and $nabla^2 f(ve(macron(x)))$ negative semi-definite. ]
]


#theorem(
  title: "Second order sufficient conditions"
)[
  If $nabla f(ve(x^*))=0$ then
  + $nabla^2 f(ve(x^*))$ positive definite $imp ve(x^*)$ is a _strict_ local minimiser.
  + $nabla^2 f(ve(x^*))$ negative definite $imp ve(x^*)$ is a _strict_ local maximiser.
  + $nabla^2 f(ve(x^*))$ indefinite $imp ve(x^*)$ is a saddle point.
  #v(1em)
  4. $nabla^2 f(ve(x^*))$ positive semi-definite $imp ve(x^*)$ is _either_ a local minimiser or a saddle point!
  5. $nabla^2 f(ve(x^*))$ negative semi-definite $imp ve(x^*)$ is _either_ a local maximiser or a saddle point! Be careful with these.

  #corollary(
    title: "Global Optimas"
  )[ From the sufficiency of stationarity as above, and under the convexity / concavity of $f in C^2 (RR^n)$:
    + $f$ convex $imp$ any stationary point is a global minimiser.
    + $f$ _strictly_ convex $imp$ stationary point is the _unique_ global minimiser.
    + $f$ concave $imp$ any stationary point is a global maximiser.
    + $f$ _strictly_ concave $imp$ stationary point is the _unique_ global maximiser. ]
]

#pagebreak()
= Equality Constraints

#definition(
  title: "Standard Form"
)[ #math.equation(
  block: true,                 
  numbering: n => margin-note(
    side: right,
    stroke: white,
    [(EP)],                                // anchor
    [ #text(6pt)[EP = equality problem] ] // note body
  ),
)[$
 op("minimise", limits: #true)_(ve(x) in Omega) #h(1cm) &f(ve(x)) \ "subject to" #h(1cm) &ve(c)_i (ve(x)) = 0 
  $
]
]<equality-problem>

#definition(
  title: "Lagrangian"
)[ For $ve(x) in RR^n$, $ve(lambda) in RR^m$, $ cal(ve(L))(ve(x),ve(lambda)) := f(ve(x)) + sum_(i=1)^m lambda_i c_(i)(ve(x)) $<lagrange-multipliers>
#note[$lambda_i$ are termed Lagrange Multipliers]
]

#definition(
  title: "Regular Point"
)[ A feasible point $macron(ve(x))$ is _regular_ $iff$ the gradients $nabla c_(i)(macron(ve(x)))$, $i=1,dots.h,m$, are linearly independent. 
#margin-note(side: left)[#text(6pt)[feasible means the constraint is satisfied at $sscript(macron(ve(x)))$ ] ] ]

#definition(
  title: "Matrix of Constraint Gradients"
)[$
A(ve(x)) = mat(nabla ve(c)_i (ve(x)), dots.h ,nabla ve(c)_m (ve(x));delim: "[") 
$]

#definition(
  title: "Jacobian"
)[$
J(ve(x)) &= A(ve(x))^T \
&= mat(nabla ve(c)_1 (ve(x))^T; dots.v ; nabla ve(c)_m (ve(x))^T;delim: "[") 
$]

#proposition(
  title: "First order necessary optimality conditions"
)[
  If $ve(x^*)$ is a local minimiser and a regular point of @equality-problem[(EP)], then $exists thin ve(lambda^*) in RR^m$ such that
  $
    nabla_x cal(L)(ve(x^*), ve(lambda^*)) = ve(0), #h(1cm) nabla_(lambda) cal(L)(ve(x^*) , ve(lambda^*)) = ve(0) 
  $<first-order-eq>
#corollary(
  title: "Constrained Stationary Point"
)[
  Any $ve(x^*)$ for which $exists thin ve(lambda^*)$ satisfying @first-order-eq[the first order conditions].
]
]


#proposition(
  title: "Second order sufficient conditions"
)[
  Let $ve(x^*)$ be a constrained stationary point of @equality-problem[(EP)] so there exist Lagrange multipliers $ve(lambda^x)$ such that
  $
    nabla_ve(x) cal(L)(ve(x^*), ve(lambda^*)) = nabla f(ve(x^*)) + A(ve(x^*)) ve(lambda^*) = ve(0) \
    nabla_ve(lambda) cal(L)(ve(x^*), ve(lambda^*)) = ve(c)(ve(x^*)) = ve(0)
  $
  If $W_Z^*$ is positive definite $imp ve(x^*)$ is a strict local minimiser.

  Here, $ A(ve(x^*)) = mat(nabla c_1(ve(x^*)), dots.h, c_(m)(ve(x^*));delim: "[") $ 
  $ W_Z^* := (Z^*)^top nabla^2_ve(x) cal(L)(ve(x^*),ve(lambda^*))Z^* $
  $ Z^* in RR^(n times (n-t^*)), #h(1cm) t^* = op("rank")(A(ve(x^*))) $
  $ (Z^*)^top A(ve(x^*)) = ve(0) $
  #remark[ where $W_Z^*$ is the reduced Hessian of the Lagrangian, and that in turn can be thought of as the projection of the Lagrangian's Hessian onto the tangent space of the constraints at the point $ve(x^*)$]
]

#pagebreak()
= Inequality Constraints


#definition(
  title: "Standard Form"
)[ #math.equation(
  block: true,                 
  numbering: n => margin-note(
    side: right,
    stroke: white,
    [(NLP)],                                // anchor
    [ #text(6pt)[NLP = non-linear problem] ] // note body
  ),
)[$
op("minimise", limits: #true)_(ve(x) in Omega) #h(1cm) &f(ve(x)) \
"subject to" #h(1cm) &ve(c)_i (ve(x)) = 0, #h(2em) i = 1, dots.h, m_E  \
&ve(c)_i (ve(x)) lt.eq 0, #h(2em) i = m_E + 1, dots.h, m  
  $
]
]<nl-problem>

#definition(title: "Convex Problem")[
  The problem @nl-problem[(NLP)] is a standard form convex optimisation problem if the objective function $f$ is convex on the feasible set, $ve(c)_i$ is affine for each $i in cal(E)$, and $ve(c)_i$ is convex for each $i in cal(I)$.
]

#definition(
  title: "Active Set"
)[
  The set of active constraints at a feasible point $ve(x)$ is
  $ cal(A)(ve(x)) = { i in 1, dots.h, m : ve(c)_i (ve(x)) = 0} $

  #note[ this concept of "active" constraints only applies to inequality constraints]
]

#definition(
  title: "Regular Point"
)[
  Feasible $ve(x^*)$ such that ${nabla c_i(ve(x^*)) : i in cal(A)(ve(x^*))}$ are linearly independent.
]

#proposition(
  title: "Constrained Stationary Point"
)[
  Feasible $ve(x^*)$ for which $exists ve(lambda_i^*)$ for $i in cal(A)(ve(x^*))$ with
  $ nabla f(ve(x^*)) + sum_(i in cal(A)(ve(x^*))) lambda_i^* nabla c_(i)(ve(x^*)) = ve(0) $
]

#theorem(
  title: "Karush Kuhn Tucker (KKT) necessary optimality conditions"
)[
  If $ve(x^*)$ is a local minimiser and a regular point, then $exists lambda_i^*$ ($i in cal(A)(ve(x^*))$) such that
  $
    nabla f(ve(x^*)) + sum_(i in cal(A)(ve(x^*))) lambda_i^* nabla c_(i)(ve(x^*)) = ve(0),
  $
  with $c_(i)(ve(x^*))=0$ $(i in cal(E))$, $c_(i)(ve(x^*)) lt.eq 0$ $(i in cal(I))$, $ lambda_i^* gt.eq 0$ $(i in cal(I))$, and $lambda_i^*=0$ for $i in.not cal(A)(ve(x^*))$.
  #note[KKT generalises @lagrange-multipliers[Lagrange Multipliers] from just equality constraints, to both equality _and_ inequality constraints.]
]<KKT>

#theorem(
  title: "Second-order sufficient conditions for strict local minimum"
)[
  Let 
  $ t^*=abs(cal(A)(ve(x^*))) $
  $ cal(A^*)=[nabla c_(i)(ve(x^*)) | i in cal(A)(ve(x^*))] $ 
  If $t^* lt n$ and $cal(A^*)$ has full rank, let 
  $ Z^* in RR^(n times (n-t^*)) $
  with 
  $ (Z^*)^(top)cal(A^*)=0 $ 
  Define
  $ W^* = nabla^2 f(ve(x^*)) + sum_(i in cal(A)(ve(x^*))) lambda_i^* nabla^2 c_(i)(ve(x^*)) $
  $ W_Z^* = (Z^*)^top W^* Z^* $
  If $ lambda_i^* gt 0, forall i in cal(I) inter cal(A)(ve(x^*)) " and " W_Z^* succ.eq 0 $ then $ve(x^*)$ is a strict local minimiser.
]

#theorem(
  title: "KKT sufficient conditions for global minimum"
)[
  If @nl-problem[(NLP)] is convex and $ve(x^*)$ satisfies the @KKT[KKT] conditions with $lambda_i^* gt.eq 0$ for all $i in cal(I) inter cal(A)(ve(x^*))$, then $ve(x^*)$ is a global minimiser.
]



#definition(
  title: "Wolfe Dual Problem"
)[
#math.equation(
  block: true,                 
  numbering: n => margin-note(
    side: right,
    stroke: white,
    [(CD)],                                // anchor
    [ #text(6pt)[CD = constrained dual] ] // note body
  ),
)[
  $
  max_(y in RR^n thin lambda in RR^m) f(y) + sum_(i=1)^m lambda_i c_(i)(ve(y)) \
  "s.t." nabla f(ve(y)) + sum_(i=1)^m lambda_i nabla c_i(ve(y)) = 0 \
  lambda_i gt 0 (i in cal(I)) 
  $
]
  #proposition(title: "Weak Duality")[
    If $ve(x)$ is primal feasible and $(ve(y), lambda)$ is dual feasible, then:
    $ f(ve(x)) >= f(ve(y)) + sum_(i=1)^m lambda_i c_(i)(ve(y)) $
  ]

  #theorem(title: "Strong Duality")[
    Under suitable constraint qualifications (e.g., Slater's condition),
    there exist primal-dual feasible points $ve(x)^*$ and $(ve(y)^*, lambda^*)$
    such that:
    $ f(ve(x)^*) = f(ve(y)^*) + sum_(i=1)^m lambda_i^* c_(i)(ve(y)^*) $
  ]
]

#pagebreak()
= Numerical Methods (unconstrained)

#definition(
  title: "Rates of convergence of iterative methods"
)[
  If $ve(x_k) => ve(x^*)$ and $(norm(ve(x_(k+1))-ve(x^*)))/(norm(ve(x_k)- ve(x^*))^alpha) => beta$ as $k => infinity$, the method has _$alpha$-th order_ convergence. 
  Key cases: 
  + $alpha=1$ (_linear_),
  + $alpha=1$ with $beta=0$ (_superlinear_), 
  + $alpha=2$ (_quadratic_).
]

#algorithm(
  title: "Line Search Methods"
)[
  Given $ve(s)^((k))$ at $ve(x)^((k))$, set $ve(x)^((k+1)) = ve(x)^((k))+ alpha^((k)) ve(s)^((k))$ where $alpha^((k))$ minimises or approximately minimises $ell_k(alpha) = f(ve(x)^((k)) + alpha ve(s)^((k)))$.

  + *Descent direction:* $(ve(g)^((k)))^top ve(s)^((k)) < 0$.
  + *Exact line search condition:* $ ell_k'(alpha) = ve(underbrace(g(x^((k))) + alpha ve(s^((k))), ve(x^(k+1))))^top ve(s)^((k)) = 0 $
  + If $ve(s)^((k))$ is a descent direction, a line search yields $alpha^((k))>0$ with $f^((k+1)) < f^((k))$.
  + *Global convergence*: convergence to a stationary point from any $ve(x)^((1))$.
  + *Quadratic termination*: method finds minimiser of a strictly convex quadratic in finite known iterations.
]

#algorithm(
  title: "Steepest Descent Method"
)[
  + *Search direction:* $ve(s)^((k)) = -ve(g)^((k))$.
  + *Descent direction:* Yes.
  + *Global convergence:* Yes.
  + *Quadratic termination:* No.
  + *Rate:* Linear with exact line searches. If $f$ is strictly convex quadratic, then for each $k$,
  $
  norm(ve(x)^(k+1) - ve(x)^*) <= ((kappa - 1)/(kappa + 1))^k norm(ve(x)^((1)) - ve(x)^*)
  $
  where $kappa$ is the condition number of $nabla^2 f$.
]

#algorithm(
  title: "Newton's Method"
)[
  + *Search direction:* solve $G^((k)) delta^((k)) = -ve(g)^((k))$ where $G^((k))$ is the Hessian.
  + *Descent direction:* Yes, if $G^((k))$ positive definite. #margin-note[#text(6pt)[this fact becomes useful in proof]]
  + *Global convergence:* No (Hessian may be singular).
  + *Quadratic termination:* Yes (one iteration for strictly convex quadratics).
  + *Rate:* Quadratic if $G^*$ positive definite.
  + *Usage:* When Hessian can be evaluated and is positive definite.
]

#algorithm(
  title: "Conjugate Gradient Method"
)[
  + *Search direction:* $ve(s)^((k)) = -ve(g)^((k)) + beta^((k)) ve(s)^((k-1))$.
  + *Descent direction:* Yes.
  + *Quadratic termination:* Yes with exact line searches.
  + *Usage:* Large $n$; stores only vectors, avoids solving linear systems.
]

#pagebreak()
= Penalty Methods

#definition(
  title: "Penalty function"
)[
#math.equation(
  block: true,                 
  numbering: n => [($P_mu$)]
)[$
  min_{x in RR^n} ( f(ve(x)) + mu P(ve(x)) ) 
  $
] where $ P(ve(x)) = sum^(m_E)_(i=1) [c_i(ve(x))]^2 + sum^m_(i=m_E + 1) [c_i(ve(x))]^2_+ $ and $ [c_i(ve(x))]_+ = max({c_i(ve(x)),0}) $
#remark()[
  + $c: RR^n arrow.r RR$ is a convex function $imp op("max"){ve(c)(ve(x)),0}^2$ is a convex function
  + $partial / (partial x_i) [op("max"){ve(c)(ve(x)),0}]^2 = 2 op("max"){ve(c)(ve(x)), 0}partial / (partial x_i)$
]
]<penalty-problem>


#theorem(
  title: "Convergence Theorem"
)[
  For each $mu>0$ let $ve(x)_(mu)$ minimise @penalty-problem[$(P_(mu))$] and set $theta(mu)=f(ve(x)_(mu))+mu P(ve(x)_(mu))$. Suppose ${ve(x)_(mu)}$ lies in a closed bounded set. Then
  $
  min_(x) { f(ve(x)) : c_(i)(ve(x))=0, thin i in cal(E), thick c_(i)(ve(x)) <= 0, i in cal(I) } = lim_(mu -> infinity) theta(mu).
  $
  Moreover, any cluster point $ve(x)^*$ of ${ve(x)_(mu)}$ solves the original problem, and $mu P(ve(x)_(mu)) -> 0$ as $mu -> infinity$.
]

#pagebreak()
= Optimal Control Theory

#definition(
  title: "Standard Form"
)[
#math.equation(
  block: true,                 
  numbering: n => margin-note(
    side: right,
    stroke: white,
    [(C)],                                // anchor
    [ #text(6pt)[C = control problem] ] // note body
  ),
)[$
    min_(ve(u)(t) in U) integral_(t_0)^(t_1) &f_0 (ve(x)(t), ve(u)(t) ) thin dif t \
    "subject to" quad accent(ve(x), dot)(t) &= ve(f) (ve(x)(t), ve(u)(t) ) \
    ve(x)(t_0) &= ve(x)_0 \
    ve(x)(t_1) &= ve(x)_1 .
  $
]
]<control-problem>

#definition(
  title: "Hamiltonian"
)[
  $
  H(ve(x), ve(hat(z)), ve(u)) = ve(hat(z))^top ve(dot(hat(x))) = sum_(i = 0)^n z_i (t) f_i (ve(x)(t), ve(u)(t) ),
  $
where $ ve(hat(z))(t)=mat(z_0(t),dots.h,z_(n)(t))^top $ and $ ve(hat(x))(t)=x_(0)(t),dots.h,x_(n)(t)]^top $ and $ x_(0)(t)=f_(0)(ve(x)(t),ve(u)(t)),\ x_(0)(t_0)=0 $
]

#definition(
  title: "Co-state Equations"
)[
  $ dot(hat(z)) = -(partial H)/(partial hat(x)) $
]

#theorem(
  title: "Autonomous, fixed targets",
  variant: "Pontryagin Maximum Principle"
)[
Suppose $(ve(x)^*,ve(u)^*)$ is optimal for @control-problem[(C)]. Then
+ $z_0 = -1$ _normal_ case), so
  $ H( ve(x),ve(hat(z)),ve(u) ) = -f_0( ve(x)(t), ve(u)(t) ) + sum_(i=1)^n z_i(t) f_i ( ve(x)(t),ve(u)(t) ). $
+ Co-state equations admit a solution $hat(ve(z))^*$.
+ $ve(u)^*$ maximises $H(ve(x)^*,ve(hat(z))^*,ve(u))$ over $u in cal(U)$.
+ $ve(x)^*$ satisfies state equation with $ve(x)^* (t_0)=x_0$, $ve(x)^* (t_1)=x_1$.
+ The Hamiltonian is constant along the optimal path and equals $0$ if $t_1$ is free.

#note()[
  Even if the problems are not autonomous or fixed, we can still convert them into autonomous, fixed target problems:

  #v(0.5cm)
*Partially free targets:* If target is intersection of $k$ surfaces $ ve(g_i)(x^1)=0$, $i=1,dots.h,k $, then the *transversality condition* is $ z_1 = sum_(i=1)^k c_i nabla g_(i)(ve(x)^1) $ for some constants $c_i$, where $ve(z)(t^1) = ve(z)^1$.

  #v(0.5cm)
*Completely free target:* If $x(t_1)$ is unrestricted, then $z(t_1)=0$.
  #v(0.5cm)

*Non-autonomous problems:* For state $ve(dot(x)) = ve(f)(ve(x),ve(u),ve(t))$ and cost $ J=integral_(t_0)^(t_1) f_0(ve(x),ve(u),t) dif t $ introduce extra state $x_(n+1)$ with $ dot(x)_(n+1) = 1 \ x_(n+1)(t_0)=t_0 \ x_(n+1)(t_1)=t_1 $
] ]

