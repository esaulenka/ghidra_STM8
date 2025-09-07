/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
//Decompile an entire program
// stolen from https://gitlab.com/CinCan/tools/-/blob/master/stable/ghidra-decompiler/DecompileHeadless.java
import java.io.*;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.Option;
import ghidra.app.util.exporter.CppExporter;
import ghidra.app.decompiler.*;
import ghidra.program.model.symbol.IdentityNameTransformer;
public class DecompileHeadless extends GhidraScript {
      
    @Override
    public void run() throws Exception {
        var program = this.getCurrentProgram();
        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(program);
        FileOutputStream fos = new FileOutputStream(new File("decompiled.c"));
        PrintWriter writer = new PrintWriter(fos);
        try {
            for(var func : program.getFunctionManager().getFunctions(true)) {
                var results = ifc.decompileFunction(func, 100000, null);
                ClangTokenGroup grp = results.getCCodeMarkup();
                if(grp != null) {
                    PrettyPrinter printer = new PrettyPrinter(results.getFunction(), grp, new IdentityNameTransformer());
                    writer.write(printer.print().getC());
                }
            }
        } finally {
            writer.close();
            fos.close();
        }
    }


}
