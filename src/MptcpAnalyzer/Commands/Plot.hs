module MptcpAnalyzer.Commands.Plot
where


plotParser :: Parser ArgsPlot
plotParser = ArgsPlot <$>
        optional ( strOption
          ( long "out" <> short 'o'
         <> help "Name of the output plot."
         <> metavar "OUT" ))
        <*> optional ( strOption
          ( long "title" <> short 't'
         <> help "Overrides the default plot title."
         <> metavar "TITLE" ))
        <*> optional ( strOption
          ( long "primary"
         <> help "Copy to X clipboard, requires `xsel` to be installed"
         <> metavar "clipboard" ))

