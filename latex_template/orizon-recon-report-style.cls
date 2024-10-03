% Orizon Report Template

%% ----------------------------------------------------------------------
%%    Setting up the class, main packages, and basic definitions
%% ----------------------------------------------------------------------

%% Class is based on the default book class and options will be passed
\NeedsTeXFormat{LaTeX2e}
\ProvidesClass{orizon-recon-report-style}[05-09-2024 v1.7.1 Orizon Report Class]

\DeclareOption*{\PassOptionsToClass{\CurrentOption}{book}}
\ProcessOptions\relax
\LoadClass[10pt,oneside]{book}

%% Main packages in the document --- Some are imported later in the class file
\RequirePackage{mathtools}
\RequirePackage{amssymb}
\RequirePackage{siunitx}

\RequirePackage{tabularx}
\RequirePackage{booktabs}
\RequirePackage{longtable}
\RequirePackage{multirow}

\RequirePackage{graphicx}
\RequirePackage{float}
\RequirePackage[labelfont=bf,justification=centering,footnotesize]{caption}
\RequirePackage{subcaption}
\RequirePackage{pdfpages}

\RequirePackage[hidelinks]{hyperref}
\RequirePackage[noabbrev]{cleveref}
\RequirePackage{xcolor}
\RequirePackage{tikz}
\RequirePackage{xspace}
\RequirePackage{microtype}

\RequirePackage{geometry}
\RequirePackage{titlesec}
\RequirePackage{titletoc}
\RequirePackage{fancyhdr}
\RequirePackage{enumitem}
\RequirePackage{etoolbox}
\RequirePackage{iftex}
\RequirePackage{datetime}
\RequirePackage{multicol}

%% Establish commands for customer name, author name, and report date
\newcommand*{\customername}[1]{\def\@customername{#1}}
\newcommand*{\authorname}[1]{\def\@authorname{#1}}
\newcommand*{\reportdate}[1]{\def\@reportdate{#1}}

%% Set the paper size to A4 landscape
\geometry{a4paper, landscape, left=1.5cm, right=1.5cm, top=2cm, bottom=2cm}

%% Set the space between columns
\setlength{\columnsep}{2cm} % Adjusted for triple spacing

%% Increase space between content and footer
\setlength{\footskip}{1.5cm} % Increased space

%% ----------------------------------------------------------------------
%%    Setting up the fonts
%% ----------------------------------------------------------------------

\ifPDFTeX
    %% With pdfLaTeX, use a fallback font (Helvetica)
    \RequirePackage[T1]{fontenc}
    \RequirePackage{helvet}
    \RequirePackage{amsmath}

    \newcommand{\titlestyle}{\fontfamily{phv}\selectfont}
    \newcommand{\largetitlestyle}{\fontfamily{phv}\bfseries\selectfont}
\else
    %% If XeLaTeX or LuaLaTeX is set as the compiler, use the uploaded custom fonts
    \RequirePackage[no-math]{fontspec}

    %% Set up Plus Jakarta Sans for body text
    \setmainfont{Plus Jakarta Sans}[
        Path = ./fonts/,
        UprightFont = PlusJakartaSans-VariableFont-wght.ttf,
        ItalicFont = PlusJakartaSans-Italic-VariableFont-wght.ttf,
        BoldFont = PlusJakartaSans-VariableFont-wght.ttf,
        BoldItalicFont = PlusJakartaSans-Italic-VariableFont-wght.ttf
    ]

    %% Set up Gill Sans for titles
    \newfontfamily\titlestyle{Gill Sans}[
        Path = ./fonts/,
        UprightFont = Gill Sans.otf
    ]

    %% Optionally, load a specific font style for larger titles
    \newfontfamily\largetitlestyle{Gill Sans}[
        Path = ./fonts/,
        BoldFont = Gill Sans Heavy.otf
    ]
\fi

%% Redefine \paragraph to be in Gill Sans Bold, #4ac300 color, and start on a new line
\titleformat{\paragraph}[block]
    {\titlestyle\bfseries\color[HTML]{4ac300}\fontsize{14}{16}\selectfont}
    {}
    {0pt}
    {}
\titlespacing*{\paragraph}{0pt}{\baselineskip}{0.5\baselineskip}

%% ----------------------------------------------------------------------
%%    Formatting the titles and table of contents
%% ----------------------------------------------------------------------

%% Format the chapter titles and spacing
\titleformat{\chapter}[display]
    {\flushright}
    {\fontsize{96}{96}\selectfont\largetitlestyle\thechapter{\color[HTML]{4ac300}.}}
    {0pt}
    {\Huge\titlestyle\bfseries}
\titlespacing*{\chapter}{0pt}{0pt}{2\baselineskip}

%% Format the section titles and spacing
\titleformat{\section}
    {\Large\titlestyle\bfseries}
    {\thesection.}
    {5pt}
    {}
\titlespacing*{\section}{0pt}{\baselineskip}{0pt}

%% Format the subsections titles and spacing
\titleformat{\subsection}
    {\large\titlestyle\bfseries}
    {\thesubsection.}
    {5pt}
    {}
\titlespacing*{\subsection}{0pt}{\baselineskip}{\baselineskip}

%% Format the subsubsections titles and spacing
\titleformat{\subsubsection}
    {\titlestyle\bfseries}
    {\thesubsubsection.}
    {5pt}
    {}
\titlespacing*{\subsubsection}{0pt}{\bigskipamount}{0pt}

%% Reduce the vertical white space between chapters in the table of contents
\dottedcontents{chapter}[1.5em]{\vspace{0.5\baselineskip}\bfseries}{1.5em}{0pt}

%% ----------------------------------------------------------------------
%%    Formatting the header and footer
%% ----------------------------------------------------------------------

%% Adjust footer with page number, logo, and copyright
\fancyfoot[L]{© Orizon \the\year\ | All rights reserved}
\fancyfoot[C]{\titlestyle\thepage}
\fancyfoot[R]{\includegraphics[width=2cm]{figures/orizon-logo-white-simplified-black.pdf}}
\pagestyle{fancy}

%% Remove header line on chapter pages
\fancypagestyle{plain}{
    \fancyhf{} % Clear all header and footer fields
    \renewcommand{\headrulewidth}{0pt} % Remove header line
    \fancyfoot[L]{© Orizon \the\year\ | All rights reserved}
    \fancyfoot[C]{\titlestyle\thepage}
    \fancyfoot[R]{\includegraphics[width=2cm]{figures/orizon-logo-white-simplified-black.pdf}}
}

%% ----------------------------------------------------------------------
%%    Setting up the \makecover command for the cover page
%% ----------------------------------------------------------------------

\usetikzlibrary{positioning}

\newcommand*{\makecover}{
    %% Use the TikZ library positioning and clear the page header and footer
    \thispagestyle{empty}

    %% Construct the cover page with TikZ
    \begin{tikzpicture}[overlay,remember picture]

        %% Add the cover background image
        \node[above=0,inner sep=0] at (current page.south) {%
            \includegraphics[width=\paperwidth,height=\paperheight]{figures/cover/orizon-recon-report-template-cover-front-background-export.jpg}};

        %% Add the ribbon image at the very top, 100pt from left side
        \node[anchor=north west,xshift=100pt,yshift=4pt] at (current page.north west) {%
            \includegraphics[height=2.1cm]{figures/cover/orizon-recon-report-template-cover-ribbon-export.png}};


        %% Add the title, centered, ~120pt from top (decreased spacing)
        \node[anchor=north,yshift=-120pt] at (current page.north) {%
            \begin{minipage}{0.9\paperwidth}
                \centering
                \color{title}\largetitlestyle\bfseries\fontsize{50}{50}\selectfont%
                    \@title \\[1ex] % Decreased space between Title and Subtitle
                %% Subtitle (removed "Service:")
                \color{white}\titlestyle\fontsize{30}{30}\selectfont%
                    Orizon RECON v2.0 \\[4ex] % Increased space after Subtitle
                %% Smaller subtitles (labels and values same size)
                \titlestyle\fontsize{20}{20}\selectfont%
                    \textbf{Customer:} \@customername \\[1ex] % Decreased space between lines
                    \textbf{Author:} \@authorname \\[1ex]
                    \textbf{Date:} \@reportdate
            \end{minipage}
        };

        %% Add the logo image at the bottom, ~80pt from bottom, centered
        \node[anchor=south,yshift=80pt] at (current page.south) {%
            \includegraphics[width=0.8\paperwidth]{figures/cover/orizon-recon-report-template-cover-front-logo-export.png}};

    \end{tikzpicture}
    \newpage
}

%% ----------------------------------------------------------------------
%%    Setting up the \makebackcover command for the back cover page
%% ----------------------------------------------------------------------

\newcommand*{\makebackcover}{
    \thispagestyle{empty}
    \begin{tikzpicture}[overlay,remember picture]

        %% Add the back cover background image
        \node[above=0,inner sep=0] at (current page.south) {%
            \includegraphics[width=\paperwidth,height=\paperheight]{figures/cover/orizon-recon-report-template-cover-back-background-export.jpg}};

        %% Add the ribbon image at the top, 100pt from left side
        \node[anchor=north west,xshift=100pt,yshift=4pt] at (current page.north west) {%
            \includegraphics[height=2cm]{figures/cover/orizon-recon-report-template-cover-ribbon-export.png}};

        %% Add the logo, centered, ~150pt from top
        \node[anchor=north,yshift=-150pt] at (current page.north) {%
            \includegraphics[height=8cm]{figures/cover/orizon-recon-report-template-cover-back-logo-export.png}};

        %% Add the contact information, centered, ~50pt below the logo
        \node[anchor=north,yshift=-420pt] at (current page.north) {%
            \begin{minipage}{0.9\paperwidth}
                \centering
                \titlestyle\fontsize{16}{16}\selectfont\color{white}%
                \textbf{Indirizzo:} Crystal Palace, Via Cefalonia 70, 25124  Brescia (BS), Italia. \\[1.5ex]
                \textbf{P.iva:} IT04484750981 \hspace{1cm} \textbf{Email:} info@orizon.one \hspace{1cm} \textbf{Tel:} (+39) 030 0946 499
            \end{minipage}
        };

    \end{tikzpicture}
    \newpage
}

%% ----------------------------------------------------------------------
%%    Setting up listings
%% ----------------------------------------------------------------------

\RequirePackage{listings}

\lstset{
  basicstyle=\ttfamily\footnotesize,
  backgroundcolor=\color{gray!10},
  keywordstyle=\color{red!75!black},
  stringstyle=\color{green!40!black},
  commentstyle=\color{blue!30!black},
  numbers=left,
  numbersep=5pt,
  numberstyle=\tiny,
  breaklines=true,
}
